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
//! In detail, the cose encrypt object contains the encrypted symmetric key as ciphertext. Currently this is encrypted with xchacha20-poly1305. The cek for the message is shared
//! to a single recipient. The currently only sharing algorithm implemented is RSA-OAEP with SHA-1, as this is currently the only public-key encryption key type supported.

use coset::{CborSerializable, iana};
use rsa::Oaep;

use crate::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, ContentFormat, CryptoError, RawPrivateKey, RawPublicKey, SignedPublicKey, SigningKey, SigningNamespace, SymmetricCryptoKey, VerifyingKey, cose::{IDENTITY_SEALED_ENVELOPE_RECIPIENT_FINGERPRINT, IDENTITY_SEALED_ENVELOPE_SENDER_FINGERPRINT, XCHACHA20_POLY1305}, traits::DeriveFingerprint, xchacha20
};

/// An identity-sealed key envelope that securely transports a symmetric key between
/// two cryptographic identities. This provides sender authentication and recipient confidentiality.
pub struct IdentitySealedKeyEnvelope {
    /// The outer COSE Sign1 structure containing the signed COSE Encrypt
    cose_sign1: coset::CoseSign1,
}

/// Errors that can occur during identity sealed key envelope operations.
#[derive(Debug)]
pub enum IdentitySealedKeyEnvelopeError {
    /// The signature verification failed
    SignatureVerificationFailed,
    /// The recipient's signed public key verification failed
    RecipientPublicKeyVerificationFailed,
    /// RSA encryption/decryption failed
    RsaOperationFailed,
    /// COSE encoding/decoding failed
    CoseEncodingFailed,
    /// The decrypted key is invalid
    InvalidKey,
    /// The namespace in the signed object does not match
    InvalidNamespace,
    /// Missing payload in COSE structure
    MissingPayload,
    /// Crypto error
    CryptoError(CryptoError),
}

impl From<CryptoError> for IdentitySealedKeyEnvelopeError {
    fn from(err: CryptoError) -> Self {
        IdentitySealedKeyEnvelopeError::CryptoError(err)
    }
}

impl IdentitySealedKeyEnvelope {
    /// Seals a symmetric key to be shared with a recipient. This requires the senders identity signature key pair, and the recipients identity verifying key, and a corresponding signed public key for encryption.
    pub fn seal(
        sender_signing_key: &SigningKey,
        recipient_verifying_key: &VerifyingKey,
        recipient_public_key: SignedPublicKey,
        key_to_share: &SymmetricCryptoKey,
    ) -> Result<Self, IdentitySealedKeyEnvelopeError> {
        let (payload, content_type) = match key_to_share.to_encoded_raw() {
            crate::EncodedSymmetricKey::BitwardenLegacyKey(bytes) => (bytes.to_vec(), ContentFormat::BitwardenLegacyKey),
            crate::EncodedSymmetricKey::CoseKey(bytes) => (bytes.to_vec(), ContentFormat::CoseKey),
        };
        let recipient_public_key = recipient_public_key
            .verify_and_unwrap(recipient_verifying_key)
            .map_err(|_| IdentitySealedKeyEnvelopeError::RecipientPublicKeyVerificationFailed)?;

        let recipient_verifying_key_fingerprint = recipient_verifying_key.fingerprint();
        let sender_verifying_key_fingerprint = sender_signing_key.to_verifying_key().fingerprint();

        // Generate CEK and encrypt it for the recipient
        let (cek, cek_alg) = (xchacha20::make_xchacha20_poly1305_key(), Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305)));

        // Encrypt the CEK for the recipient using their public key
        let (recipient_cek_ct, recipient_alg) = match recipient_public_key.inner() {
            RawPublicKey::RsaOaepSha1(rsa_public_key) => {
                (crate::rsa::encrypt_rsa2048_oaep_sha1(rsa_public_key, &cek)
                    .map_err(|_| IdentitySealedKeyEnvelopeError::RsaOperationFailed)?, Some(coset::Algorithm::Assigned(iana::Algorithm::RSAES_OAEP_RFC_8017_default)))
            }
        };

        // Build COSE Encrypt structure with the encrypted key as ciphertext
        // The recipient info contains the algorithm used
        let mut nonce = Vec::new();
        let cose_encrypt = coset::CoseEncryptBuilder::new()
            .protected(
                {
                    let mut hdr = coset::HeaderBuilder::new()
                        .value(IDENTITY_SEALED_ENVELOPE_RECIPIENT_FINGERPRINT, ciborium::Value::Bytes(recipient_verifying_key_fingerprint.0.to_vec()))
                        .value(IDENTITY_SEALED_ENVELOPE_SENDER_FINGERPRINT, ciborium::Value::Bytes(sender_verifying_key_fingerprint.0.to_vec()))
                        .build();
                    hdr.alg = cek_alg.clone();
                    hdr
                }
            )
            .add_recipient(
                coset::CoseRecipientBuilder::new()
                    .protected(
                        {
                            let mut hdr = coset::HeaderBuilder::new()
                                .build();
                            hdr.alg = recipient_alg;
                            hdr
                        }
                    )
                    .ciphertext(recipient_cek_ct)
                    .build(),
            )
            .try_create_ciphertext(&payload, &[], |data, aad| {
                match cek_alg {
                    Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305)) => {
                        let ciphertext =
                            crate::xchacha20::encrypt_xchacha20_poly1305(&cek, data, aad);
                        nonce = ciphertext.nonce().to_vec();
                        Ok(ciphertext.encrypted_bytes().to_vec())
                    },
                    _ => return Err(IdentitySealedKeyEnvelopeError::InvalidKey),
                }
            })?
            .unprotected(coset::HeaderBuilder::new().iv(nonce).build())
            .build();

        // Sign the COSE Encrypt structure
        
    }

    pub fn unseal(
        &self,
        sender_verifying_key: &VerifyingKey,
        recipient_private_key: &AsymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, IdentitySealedKeyEnvelopeError> {
        todo!()
    }
}
