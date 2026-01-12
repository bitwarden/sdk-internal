//! Identity sealed key envelope is used to transport a key between two cryptographic identities.
//!
//! It implements signcryption of a key. The cryptographic objects strongly binds to the receiving
//! and sending cryptographic identities. The interfaces also require a cryptographic attestation,
//! where the recipient provides a claim over the public encryption key it is receiving on.
//!
//! The envelope is structured as a COSE Sign1 object (for sender authentication) containing
//! a COSE Encrypt object (for confidentiality). This provides:
//! - Confidentiality: Only the intended recipient can decrypt the key
//! - Authenticity: The recipient can verify the sender's identity
//! - Binding: The envelope is bound to both sender and recipient identities
//!
//! In detail, the cose encrypt object contains the encrypted symmetric key as ciphertext. Currently
//! this is encrypted with xchacha20-poly1305. The cek for the message is shared to a single
//! recipient. The currently only sharing algorithm implemented is RSA-OAEP with SHA-1, as this is
//! currently the only public-key encryption key type supported.

use std::str::FromStr;

use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use coset::{
    CborSerializable,
    iana::{self, CoapContentFormat},
};
use rsa::Oaep;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use super::idenity::{OtherIdentity, SelfIdentity};
use crate::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, BitwardenLegacyKeyBytes, ContentFormat,
    CoseKeyBytes, EncodedSymmetricKey, KeyIds, RawPrivateKey, RawPublicKey, SigningKey,
    SigningNamespace, SymmetricCryptoKey, VerifyingKey,
    cose::{
        CONTENT_TYPE_BITWARDEN_LEGACY_KEY, IDENTITY_SEALED_ENVELOPE_RECIPIENT_FINGERPRINT,
        IDENTITY_SEALED_ENVELOPE_SENDER_FINGERPRINT, XCHACHA20_POLY1305,
    },
    traits::{DeriveFingerprint, KeyFingerprint},
    xchacha20,
};

/// An identity-sealed key envelope that securely transports a symmetric key between
/// two cryptographic identities. This provides sender authentication and recipient confidentiality.
pub struct IdentitySealedKeyEnvelope {
    /// The outer COSE Sign1 structure containing the signed COSE Encrypt
    cose_sign1: coset::CoseSign1,
}

/// Errors that can occur during identity sealed key envelope sealing operations. This is internal
/// only. The publicly exposed API surface does not expose these errors directly, as consumers
/// cannot handle them in a meaningful way. Instead, these are meant for adding debug information
/// via the instrument macro.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum SealError {
    /// A crypto operation such as signature generation or encryption failed
    #[error("Sealing Failed")]
    SealFailed,
}

/// Errors that can occur during identity sealed key envelope unsealing operations. This is internal
/// only. The publicly exposed API surface does not expose these errors directly, as consumers
/// cannot handle them in a meaningful way. Instead, these are meant for adding debug information
/// via the instrument macro.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum UnsealError {
    /// The recipient is incorrect
    #[error("The recipient is incorrect")]
    RecipientMismatch,
    /// A crypto operation such as signature verification or decryption failed
    #[error("Unsealing failed")]
    UnsealFailed,
}

impl IdentitySealedKeyEnvelope {
    /// Seals a symmetric key to be shared with a recipient. This requires the sender's `SelfIdentity` and
    /// the recipient's `OtherIdentity`.
    pub fn seal(
        sender: &SelfIdentity<'_, impl KeyIds>,
        recipient: &OtherIdentity,
        key_to_share: &SymmetricCryptoKey,
    ) -> Result<Self, SealError> {
        #[allow(deprecated)]
        let sender_signing_key = sender
            .context()
            .dangerous_get_signing_key(sender.signing_key_id())
            .map_err(|_| SealError::SealFailed)?;

        Self::seal_ref(
            &sender_signing_key,
            recipient.verifying_key(),
            recipient.public_key(),
            key_to_share,
        )
    }

    /// Seals a symmetric key to be shared with a recipient. This requires the senders identity
    /// signature key pair, the recipients identity verifying key, and a verified public key for
    /// encryption.
    ///
    /// Note: The `recipient_public_key` must have been verified to belong to the identity
    /// represented by `recipient_verifying_key` before calling this method. This is typically
    /// done by constructing an `OtherIdentity` which performs this verification.
    #[instrument(level = "error", skip_all, err)]
    #[allow(unused)]
    fn seal_ref(
        sender_signing_key: &SigningKey,
        recipient_verifying_key: &VerifyingKey,
        recipient_public_key: &AsymmetricPublicCryptoKey,
        key_to_share: &SymmetricCryptoKey,
    ) -> Result<Self, SealError> {
        // Derive fingerprints for sender and recipient
        let recipient_verifying_key_fingerprint = recipient_verifying_key.fingerprint();
        let sender_verifying_key_fingerprint = sender_signing_key.to_verifying_key().fingerprint();

        // Encode the symmetric key to a byte representation plus content format
        let (payload, content_type) = match key_to_share.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(bytes) => {
                (bytes.to_vec(), ContentFormat::BitwardenLegacyKey)
            }
            EncodedSymmetricKey::CoseKey(bytes) => (bytes.to_vec(), ContentFormat::CoseKey),
        };

        // Encryption process:
        // 1. Generate a content encryption key (CEK) for xchacha20-poly1305
        // Generate CEK and encrypt it for the recipient
        let (cek, cek_alg) = make_cek();

        // Encrypt the CEK for the recipient using their public key
        let (recipient_cek_ct, recipient_alg) = match recipient_public_key.inner() {
            RawPublicKey::RsaOaepSha1(rsa_public_key) => (
                crate::rsa::encrypt_rsa2048_oaep_sha1(rsa_public_key, &cek)
                    .map_err(|_| SealError::SealFailed)?,
                Some(coset::Algorithm::Assigned(
                    iana::Algorithm::RSAES_OAEP_RFC_8017_default,
                )),
            ),
        };

        // Build COSE Encrypt structure with the encrypted key as ciphertext
        // The recipient info contains the algorithm used
        let mut nonce = Vec::new();
        let cose_encrypt = coset::CoseEncryptBuilder::new()
            .protected({
                let mut hdr = coset::HeaderBuilder::new()
                    .value(
                        IDENTITY_SEALED_ENVELOPE_RECIPIENT_FINGERPRINT,
                        ciborium::Value::Bytes(recipient_verifying_key_fingerprint.0.to_vec()),
                    )
                    .value(
                        IDENTITY_SEALED_ENVELOPE_SENDER_FINGERPRINT,
                        ciborium::Value::Bytes(sender_verifying_key_fingerprint.0.to_vec()),
                    );
                match content_type {
                    ContentFormat::BitwardenLegacyKey => {
                        hdr = hdr.content_type(CONTENT_TYPE_BITWARDEN_LEGACY_KEY.to_string());
                    }
                    ContentFormat::CoseKey => {
                        hdr = hdr.content_format(CoapContentFormat::CoseKey);
                    }
                    _ => return Err(SealError::SealFailed),
                }
                let mut hdr = hdr.build();
                hdr.alg = Some(cek_alg.clone());
                hdr
            })
            .add_recipient(
                coset::CoseRecipientBuilder::new()
                    .protected({
                        let mut hdr = coset::HeaderBuilder::new().build();
                        hdr.alg = recipient_alg;
                        hdr
                    })
                    .ciphertext(recipient_cek_ct)
                    .build(),
            )
            .try_create_ciphertext(&payload, &[], |data, aad| -> Result<Vec<u8>, SealError> {
                match cek_alg {
                    coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) => {
                        let cek: [u8; xchacha20::KEY_SIZE] =
                            cek.try_into().map_err(|_| SealError::SealFailed)?;
                        let ciphertext =
                            crate::xchacha20::encrypt_xchacha20_poly1305(&cek, data, aad);
                        nonce = ciphertext.nonce().to_vec();
                        Ok(ciphertext.encrypted_bytes().to_vec())
                    }
                    _ => Err(SealError::SealFailed),
                }
            })?
            .unprotected(coset::HeaderBuilder::new().iv(nonce).build())
            .build()
            .to_vec()
            .map_err(|_| SealError::SealFailed)?;

        // Sign the COSE Encrypt structure with the sender's signing key
        // The signature binds the encrypted content to the sender's identity
        let cose_sign1 = coset::CoseSign1Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(sender_signing_key.cose_algorithm())
                    .key_id((&sender_signing_key.id).into())
                    .value(
                        crate::cose::SIGNING_NAMESPACE,
                        ciborium::Value::Integer(ciborium::value::Integer::from(
                            SigningNamespace::IdentitySealedKeyEnvelope.as_i64(),
                        )),
                    )
                    .build(),
            )
            .payload(cose_encrypt)
            .create_signature(&[], |data| sender_signing_key.sign_raw(data))
            .build();

        Ok(Self { cose_sign1 })
    }

    /// Unseals the envelope and extracts the shared symmetric key.
    ///
    /// To unseal correctly, this requires the sender's verifying key, the recipient's verifying
    /// key to match the key pairs used during sealing, and the private key to be the private key
    /// corresponding to the signed public key used during sealing.
    #[instrument(level = "error", skip_all, err)]
    #[allow(unused)]
    fn unseal_ref(
        &self,
        sender_verifying_key: &VerifyingKey,
        recipient_verifying_key: &VerifyingKey,
        recipient_private_key: &AsymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, UnsealError> {
        // Cryptographic Safety: To unseal the envelope, while guaranteeing the security properties,
        // the following must be verified:
        // 1. The signature namespace must be IdentitySealedKeyEnvelope
        // 2. The protected header of the contained COSE Encrypt structure must contain: a. The
        //    sender fingerprint matching the sender verifying key b. The recipient fingerprint
        //    matching the recipient verifying key
        // 3. The correct algorithm must be used for the CEK, the recipient ciphertext, and the
        //    signature

        // 1. Verify the namespace in the signature
        let namespace = crate::signing::namespace(&self.cose_sign1.protected)
            .map_err(|_| UnsealError::UnsealFailed)?;
        if namespace != SigningNamespace::IdentitySealedKeyEnvelope {
            return Err(UnsealError::UnsealFailed);
        }
        self.cose_sign1
            .verify_signature(&[], |sig, data| sender_verifying_key.verify_raw(sig, data))
            .map_err(|_| UnsealError::UnsealFailed)?;

        // The signature is verified. This means the outer message is verified to have come from the
        // sender (Sender authentication). However, the same cannot be claimed
        // for the contents of the contained COSE Encrypt message could have been stripped and
        // relayed by the sender. To prove that the sender knows and sent the contents of
        // the COSE Encrypt message, authenticate the protected header containing the sender
        // fingerprint, and the recipient fingerprint.
        let cose_encrypt_bytes = self
            .cose_sign1
            .payload
            .as_ref()
            .ok_or(UnsealError::UnsealFailed)?;
        // Parse the COSE Encrypt structure
        let cose_encrypt = coset::CoseEncrypt::from_slice(cose_encrypt_bytes)
            .map_err(|_| UnsealError::UnsealFailed)?;

        // Verify the sender and recipient fingerprints
        // Extract and verify the sender fingerprint from the COSE Encrypt protected header
        let sender_fingerprint_in_envelope = extract_fingerprint_from_header(
            &cose_encrypt.protected.header,
            IDENTITY_SEALED_ENVELOPE_SENDER_FINGERPRINT,
        )
        .map_err(|_| UnsealError::UnsealFailed)?;
        if sender_fingerprint_in_envelope != sender_verifying_key.fingerprint() {
            return Err(UnsealError::UnsealFailed);
        }
        // Extract and verify the recipient fingerprint from the COSE Encrypt protected header
        let recipient_fingerprint_in_envelope = extract_fingerprint_from_header(
            &cose_encrypt.protected.header,
            IDENTITY_SEALED_ENVELOPE_RECIPIENT_FINGERPRINT,
        )
        .map_err(|_| UnsealError::UnsealFailed)?;
        if recipient_fingerprint_in_envelope != recipient_verifying_key.fingerprint() {
            return Err(UnsealError::RecipientMismatch);
        }

        // Decrypt the CEK
        // Get the recipient
        let recipient = cose_encrypt
            .recipients
            .first()
            .ok_or(UnsealError::UnsealFailed)?;
        // Get the CEK algorithm from the protected header
        let cek_alg = cose_encrypt
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(UnsealError::UnsealFailed)?;
        // Get the encrypted CEK from the recipient
        let encrypted_cek = recipient
            .ciphertext
            .as_ref()
            .ok_or(UnsealError::UnsealFailed)?;
        // Decrypt the CEK using the recipient's private key
        let cek = match recipient.protected.header.alg {
            Some(coset::Algorithm::Assigned(iana::Algorithm::RSAES_OAEP_RFC_8017_default)) => {
                match recipient_private_key.inner() {
                    RawPrivateKey::RsaOaepSha1(rsa_private_key) => rsa_private_key
                        .decrypt(Oaep::new::<sha1::Sha1>(), encrypted_cek)
                        .map_err(|_| UnsealError::UnsealFailed)?,
                }
            }
            _ => {
                return Err(UnsealError::UnsealFailed);
            }
        };

        // Get the nonce from the unprotected header
        let nonce = cose_encrypt.unprotected.iv.as_slice();

        // Get the ciphertext
        #[allow(deprecated)]
        let decrypted = cose_encrypt
            .decrypt(&[], |data, aad| match cek_alg {
                coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) => {
                    let cek = {
                        let mut cek_arr = [0u8; xchacha20::KEY_SIZE];
                        cek_arr.copy_from_slice(&cek);
                        cek_arr
                    };
                    let nonce: [u8; xchacha20::NONCE_SIZE] = match nonce.try_into() {
                        Ok(n) => n,
                        Err(_) => return Err(UnsealError::UnsealFailed),
                    };
                    crate::xchacha20::decrypt_xchacha20_poly1305(&nonce, &cek, data, aad)
                        .map_err(|_| UnsealError::UnsealFailed)
                }
                _ => return Err(UnsealError::UnsealFailed),
            })
            .map_err(|_| UnsealError::UnsealFailed)?;

        let content_format = ContentFormat::try_from(&cose_encrypt.protected.header)
            .map_err(|_| UnsealError::UnsealFailed)?;
        let symmetric_key = match content_format {
            ContentFormat::BitwardenLegacyKey => EncodedSymmetricKey::BitwardenLegacyKey(
                BitwardenLegacyKeyBytes::try_from(decrypted)
                    .map_err(|_| UnsealError::UnsealFailed)?,
            ),
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(
                CoseKeyBytes::try_from(decrypted).map_err(|_| UnsealError::UnsealFailed)?,
            ),
            _ => {
                return Err(UnsealError::UnsealFailed);
            }
        };
        SymmetricCryptoKey::try_from(symmetric_key).map_err(|_| UnsealError::UnsealFailed)
    }

    /// Unseals the envelope and extracts the shared symmetric key using identity types.
    ///
    /// This method takes a `SelfIdentity` (the recipient) and an `OtherIdentity` (the sender)
    /// and unseals the key if the recipient is the intended recipient and the sender is verified.
    #[instrument(level = "error", skip_all, err)]
    #[allow(unused)]
    pub fn unseal<Ids: KeyIds>(
        &self,
        recipient: &SelfIdentity<'_, Ids>,
        sender: &OtherIdentity,
    ) -> Result<SymmetricCryptoKey, UnsealError> {
        #[allow(deprecated)]
        let recipient_private_key = recipient
            .context()
            .dangerous_get_asymmetric_key(recipient.private_key_id())
            .map_err(|_| UnsealError::UnsealFailed)?;

        let recipient_verifying_key = recipient
            .context()
            .get_verifying_key(recipient.signing_key_id())
            .map_err(|_| UnsealError::UnsealFailed)?;

        self.unseal_ref(
            sender.verifying_key(),
            &recipient_verifying_key,
            recipient_private_key,
        )
    }
}

fn make_cek() -> (Vec<u8>, coset::Algorithm) {
    let cek = xchacha20::make_xchacha20_poly1305_key();
    (
        cek.to_vec(),
        coset::Algorithm::PrivateUse(XCHACHA20_POLY1305),
    )
}

fn extract_fingerprint_from_header(
    header: &coset::Header,
    label: i64,
) -> Result<KeyFingerprint, ()> {
    let fingerprint_bytes = header
        .rest
        .iter()
        .find_map(|(key, value)| {
            if let coset::Label::Int(key) = key {
                if *key == label {
                    return value.as_bytes().map(|b| b.to_vec());
                }
            }
            None
        })
        .ok_or(())?;
    Ok(KeyFingerprint(
        fingerprint_bytes.try_into().map_err(|_| ())?,
    ))
}

// Conversion implementations

impl From<&IdentitySealedKeyEnvelope> for Vec<u8> {
    fn from(val: &IdentitySealedKeyEnvelope) -> Self {
        val.cose_sign1
            .clone()
            .to_vec()
            .expect("COSE Sign1 serialization should never fail")
    }
}

impl TryFrom<Vec<u8>> for IdentitySealedKeyEnvelope {
    type Error = ();

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let cose_sign1 = coset::CoseSign1::from_slice(&data).map_err(|_| ())?;
        Ok(IdentitySealedKeyEnvelope { cose_sign1 })
    }
}

impl std::fmt::Debug for IdentitySealedKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentitySealedKeyEnvelope").finish()
    }
}

impl FromStr for IdentitySealedKeyEnvelope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| ())?;
        Self::try_from(data.into_bytes())
    }
}

impl From<IdentitySealedKeyEnvelope> for String {
    fn from(val: IdentitySealedKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for IdentitySealedKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|_| {
            serde::de::Error::custom("Failed to deserialize IdentitySealedKeyEnvelope")
        })
    }
}

impl Serialize for IdentitySealedKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

impl std::fmt::Display for IdentitySealedKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let serialized: Vec<u8> = self.into();
        write!(f, "{}", B64::from(serialized))
    }
}

// WASM bindings

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type IdentitySealedKeyEnvelope = Tagged<string, "IdentitySealedKeyEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for IdentitySealedKeyEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for IdentitySealedKeyEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;

        let s = unsafe { String::from_abi(abi) };
        Self::from_str(&s).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AsymmetricCryptoKey, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
        SignedPublicKeyMessage, SymmetricCryptoKey,
    };

    #[test]
    fn test_seal_unseal_roundtrip() {
        // Create sender's signing key pair
        let sender_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let sender_verifying_key = sender_signing_key.to_verifying_key();

        // Create recipient's signing key pair (for identity)
        let recipient_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);

        // Create recipient's encryption key pair
        let recipient_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let recipient_public_key = recipient_private_key.to_public_key();

        // Sign the recipient's public key with their signing key
        let signed_public_key = SignedPublicKeyMessage::from_public_key(&recipient_public_key)
            .expect("Failed to create signed public key message")
            .sign(&recipient_signing_key)
            .expect("Failed to sign public key");

        // Create OtherIdentity for the recipient
        let recipient_identity =
            OtherIdentity::try_from((signed_public_key, recipient_signing_key.to_verifying_key()))
                .expect("Failed to create recipient identity");

        // Create a symmetric key to share
        let key_to_share = SymmetricCryptoKey::make_xchacha20_poly1305_key();

        // Seal the key
        let envelope = IdentitySealedKeyEnvelope::seal_ref(
            &sender_signing_key,
            recipient_identity.verifying_key(),
            recipient_identity.public_key(),
            &key_to_share,
        )
        .expect("Failed to seal key");

        // Unseal the key
        let unsealed_key = envelope
            .unseal_ref(
                &sender_verifying_key,
                recipient_identity.verifying_key(),
                &recipient_private_key,
            )
            .expect("Failed to unseal key");

        // Verify the key matches
        assert_eq!(
            key_to_share.to_base64(),
            unsealed_key.to_base64(),
            "Unsealed key does not match original key"
        );
    }

    #[test]
    fn test_unseal_fails_with_wrong_sender_key() {
        // Create sender's signing key pair
        let sender_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);

        // Create a different sender's key (attacker)
        let wrong_sender_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let wrong_sender_verifying_key = wrong_sender_signing_key.to_verifying_key();

        // Create recipient's signing key pair
        let recipient_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);

        // Create recipient's encryption key pair
        let recipient_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let recipient_public_key = recipient_private_key.to_public_key();

        // Sign the recipient's public key
        let signed_public_key = SignedPublicKeyMessage::from_public_key(&recipient_public_key)
            .expect("Failed to create signed public key message")
            .sign(&recipient_signing_key)
            .expect("Failed to sign public key");

        // Create OtherIdentity for the recipient
        let recipient_identity =
            OtherIdentity::try_from((signed_public_key, recipient_signing_key.to_verifying_key()))
                .expect("Failed to create recipient identity");

        // Create a symmetric key to share
        let key_to_share = SymmetricCryptoKey::make_xchacha20_poly1305_key();

        // Seal the key with the real sender
        let envelope = IdentitySealedKeyEnvelope::seal_ref(
            &sender_signing_key,
            recipient_identity.verifying_key(),
            recipient_identity.public_key(),
            &key_to_share,
        )
        .expect("Failed to seal key");

        // Try to unseal with wrong sender's verifying key - should fail
        let result = envelope.unseal_ref(
            &wrong_sender_verifying_key,
            recipient_identity.verifying_key(),
            &recipient_private_key,
        );
        assert!(
            matches!(result, Err(UnsealError::UnsealFailed)),
            "Expected signature verification to fail with wrong sender key"
        );
    }

    #[test]
    fn test_unseal_fails_with_wrong_recipient_key() {
        // Create sender's signing key pair
        let sender_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let sender_verifying_key = sender_signing_key.to_verifying_key();

        // Create recipient's signing key pair
        let recipient_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);

        // Create recipient's encryption key pair
        let recipient_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let recipient_public_key = recipient_private_key.to_public_key();

        // Create a different recipient's private key (attacker)
        let wrong_recipient_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        // Sign the recipient's public key
        let signed_public_key = SignedPublicKeyMessage::from_public_key(&recipient_public_key)
            .expect("Failed to create signed public key message")
            .sign(&recipient_signing_key)
            .expect("Failed to sign public key");

        // Create OtherIdentity for the recipient
        let recipient_identity =
            OtherIdentity::try_from((signed_public_key, recipient_signing_key.to_verifying_key()))
                .expect("Failed to create recipient identity");

        // Create a symmetric key to share
        let key_to_share = SymmetricCryptoKey::make_xchacha20_poly1305_key();

        // Seal the key
        let envelope = IdentitySealedKeyEnvelope::seal_ref(
            &sender_signing_key,
            recipient_identity.verifying_key(),
            recipient_identity.public_key(),
            &key_to_share,
        )
        .expect("Failed to seal key");

        // Try to unseal with wrong recipient's private key - should fail
        let result = envelope.unseal_ref(
            &sender_verifying_key,
            recipient_identity.verifying_key(),
            &wrong_recipient_private_key,
        );
        assert!(
            matches!(result, Err(UnsealError::UnsealFailed)),
            "Expected RSA decryption to fail with wrong recipient key"
        );
    }

    /// Generates test vectors for the identity sealed key envelope.
    /// Run with: cargo test -p bitwarden-crypto generate_test_vectors -- --ignored --nocapture
    #[test]
    #[ignore]
    fn generate_test_vectors() {
        use crate::CoseSerializable;

        // Create sender's signing key pair
        let sender_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let sender_verifying_key = sender_signing_key.to_verifying_key();

        // Create recipient's signing key pair (for identity)
        let recipient_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);

        // Create recipient's encryption key pair
        let recipient_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let recipient_public_key = recipient_private_key.to_public_key();

        // Sign the recipient's public key with their signing key
        let signed_public_key = SignedPublicKeyMessage::from_public_key(&recipient_public_key)
            .expect("Failed to create signed public key message")
            .sign(&recipient_signing_key)
            .expect("Failed to sign public key");

        // Create OtherIdentity for the recipient
        let recipient_identity = OtherIdentity::try_from((
            signed_public_key.clone(),
            recipient_signing_key.to_verifying_key(),
        ))
        .expect("Failed to create recipient identity");

        // Create a symmetric key to share
        let key_to_share = SymmetricCryptoKey::make_xchacha20_poly1305_key();

        // Seal the key
        let envelope = IdentitySealedKeyEnvelope::seal_ref(
            &sender_signing_key,
            recipient_identity.verifying_key(),
            recipient_identity.public_key(),
            &key_to_share,
        )
        .expect("Failed to seal key");

        // Verify roundtrip works
        let unsealed_key = envelope
            .unseal_ref(
                &sender_verifying_key,
                recipient_identity.verifying_key(),
                &recipient_private_key,
            )
            .expect("Failed to unseal key");
        assert_eq!(key_to_share.to_base64(), unsealed_key.to_base64());

        // Print test vectors
        let recipient_verifying_key = recipient_signing_key.to_verifying_key();
        println!("// Test vectors for IdentitySealedKeyEnvelope");
        println!(
            "const TEST_SENDER_SIGNING_KEY: &str = \"{}\";",
            B64::from(sender_signing_key.to_cose().as_ref())
        );
        println!(
            "const TEST_SENDER_VERIFYING_KEY: &str = \"{}\";",
            B64::from(sender_verifying_key.to_cose().as_ref())
        );
        println!(
            "const TEST_RECIPIENT_SIGNING_KEY: &str = \"{}\";",
            B64::from(recipient_signing_key.to_cose().as_ref())
        );
        println!(
            "const TEST_RECIPIENT_VERIFYING_KEY: &str = \"{}\";",
            B64::from(recipient_verifying_key.to_cose().as_ref())
        );
        println!(
            "const TEST_RECIPIENT_PRIVATE_KEY: &str = \"{}\";",
            B64::from(
                recipient_private_key
                    .to_der()
                    .expect("Failed to serialize private key")
                    .as_ref()
            )
        );
        println!(
            "const TEST_SIGNED_PUBLIC_KEY: &str = \"{}\";",
            String::from(signed_public_key)
        );
        println!(
            "const TEST_KEY_TO_SHARE: &str = \"{}\";",
            key_to_share.to_base64()
        );
        println!(
            "const TEST_ENVELOPE: &str = \"{}\";",
            String::from(envelope)
        );
    }
}
