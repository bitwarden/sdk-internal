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

use coset::{CborSerializable, iana};
use rsa::Oaep;

use crate::{
    AsymmetricCryptoKey, CryptoError, RawPrivateKey, RawPublicKey, SignedPublicKey, SigningKey,
    SigningNamespace, SymmetricCryptoKey, VerifyingKey,
};

/// An identity-sealed key envelope that securely transports a symmetric key between
/// two cryptographic identities.
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
    /// Seals a symmetric key for transport to a recipient.
    ///
    /// The process:
    /// 1. Verify the recipient's public key against their verifying key
    /// 2. Encrypt the key using RSA-OAEP with the recipient's public key (COSE Encrypt)
    /// 3. Sign the encrypted blob with the sender's signing key (COSE Sign1)
    ///
    /// # Arguments
    /// * `sender_signing_key` - The sender's signing key for authentication
    /// * `recipient_verifying_key` - The recipient's verifying key to verify their public key
    /// * `recipient_public_key` - The recipient's signed public encryption key
    /// * `key_to_share` - The symmetric key to securely share
    pub fn seal(
        sender_signing_key: &SigningKey,
        recipient_verifying_key: &VerifyingKey,
        recipient_public_key: SignedPublicKey,
        key_to_share: &SymmetricCryptoKey,
    ) -> Result<Self, IdentitySealedKeyEnvelopeError> {
        let recipient_public_key = recipient_public_key
            .verify_and_unwrap(recipient_verifying_key)
            .map_err(|_| IdentitySealedKeyEnvelopeError::RecipientPublicKeyVerificationFailed)?;

        // Get the key bytes to encrypt
        let key_bytes = key_to_share.to_encoded();

        // Encrypt with RSA-OAEP-SHA1
        let encrypted_key = match recipient_public_key.inner() {
            RawPublicKey::RsaOaepSha1(rsa_public_key) => {
                crate::rsa::encrypt_rsa2048_oaep_sha1(rsa_public_key, key_bytes.as_ref())
                    .map_err(|_| IdentitySealedKeyEnvelopeError::RsaOperationFailed)?
            }
        };

        // Build COSE Encrypt structure with the encrypted key as ciphertext
        // The recipient info contains the algorithm used
        let cose_encrypt = coset::CoseEncryptBuilder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(iana::Algorithm::Direct)
                    .build(),
            )
            .add_recipient(
                coset::CoseRecipientBuilder::new()
                    .protected(
                        coset::HeaderBuilder::new()
                            .algorithm(iana::Algorithm::RSA_OAEP)
                            .build(),
                    )
                    .ciphertext(encrypted_key)
                    .build(),
            )
            .build();

        // Serialize the COSE Encrypt to bytes
        let cose_encrypt_bytes = cose_encrypt
            .to_vec()
            .map_err(|_| IdentitySealedKeyEnvelopeError::CoseEncodingFailed)?;

        // Sign the COSE Encrypt bytes with the sender's signing key
        let cose_sign1 = coset::CoseSign1Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(sender_signing_key.cose_algorithm())
                    .key_id(Vec::from(&sender_signing_key.id))
                    .content_format(iana::CoapContentFormat::CoseEncrypt)
                    .value(
                        crate::cose::SIGNING_NAMESPACE,
                        ciborium::Value::Integer(
                            SigningNamespace::IdentitySealedKeyEnvelope.as_i64().into(),
                        ),
                    )
                    .build(),
            )
            .payload(cose_encrypt_bytes)
            .create_signature(&[], |data| sender_signing_key.sign_raw(data))
            .build();

        Ok(Self { cose_sign1 })
    }

    /// Unseals a key envelope and returns the shared symmetric key.
    ///
    /// The process:
    /// 1. Verify the signature using the sender's verifying key
    /// 2. Parse the COSE Encrypt from the signed payload
    /// 3. Decrypt the key using the recipient's private key
    ///
    /// # Arguments
    /// * `sender_verifying_key` - The sender's verifying key to verify the signature
    /// * `recipient_private_key` - The recipient's private key for decryption
    pub fn unseal(
        &self,
        sender_verifying_key: &VerifyingKey,
        recipient_private_key: &AsymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, IdentitySealedKeyEnvelopeError> {
        // Verify the signature
        self.cose_sign1
            .verify_signature(&[], |sig, data| sender_verifying_key.verify_raw(sig, data))
            .map_err(|_| IdentitySealedKeyEnvelopeError::SignatureVerificationFailed)?;

        // Verify the namespace
        let namespace = self
            .cose_sign1
            .protected
            .header
            .rest
            .iter()
            .find_map(|(key, value)| {
                if let coset::Label::Int(key) = key {
                    if *key == crate::cose::SIGNING_NAMESPACE {
                        return value.as_integer();
                    }
                }
                None
            })
            .ok_or(IdentitySealedKeyEnvelopeError::InvalidNamespace)?;

        let expected_namespace = SigningNamespace::IdentitySealedKeyEnvelope.as_i64();
        if i128::from(namespace) != expected_namespace as i128 {
            return Err(IdentitySealedKeyEnvelopeError::InvalidNamespace);
        }

        // Extract the payload (COSE Encrypt bytes)
        let cose_encrypt_bytes = self
            .cose_sign1
            .payload
            .as_ref()
            .ok_or(IdentitySealedKeyEnvelopeError::MissingPayload)?;

        // Parse the COSE Encrypt
        let cose_encrypt = coset::CoseEncrypt::from_slice(cose_encrypt_bytes)
            .map_err(|_| IdentitySealedKeyEnvelopeError::CoseEncodingFailed)?;

        // Get the encrypted key from the first recipient
        let recipient = cose_encrypt
            .recipients
            .first()
            .ok_or(IdentitySealedKeyEnvelopeError::CoseEncodingFailed)?;

        let encrypted_key = recipient
            .ciphertext
            .as_ref()
            .ok_or(IdentitySealedKeyEnvelopeError::MissingPayload)?;

        // Decrypt with RSA-OAEP-SHA1
        let decrypted_key_bytes = match recipient_private_key.inner() {
            RawPrivateKey::RsaOaepSha1(rsa_private_key) => rsa_private_key
                .decrypt(Oaep::new::<sha1::Sha1>(), encrypted_key)
                .map_err(|_| IdentitySealedKeyEnvelopeError::RsaOperationFailed)?,
        };

        // Parse the decrypted bytes back into a SymmetricCryptoKey
        SymmetricCryptoKey::try_from(
            &crate::BitwardenLegacyKeyBytes::from(decrypted_key_bytes),
        )
        .map_err(|_| IdentitySealedKeyEnvelopeError::InvalidKey)
    }

    /// Serializes the envelope to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentitySealedKeyEnvelopeError> {
        self.cose_sign1
            .to_vec()
            .map_err(|_| IdentitySealedKeyEnvelopeError::CoseEncodingFailed)
    }

    /// Deserializes an envelope from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentitySealedKeyEnvelopeError> {
        let cose_sign1 = coset::CoseSign1::from_slice(bytes)
            .map_err(|_| IdentitySealedKeyEnvelopeError::CoseEncodingFailed)?;
        Ok(Self { cose_sign1 })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_identity_sealed_key_envelope() {}
}
