//! Cryptographic identities act as an abstraction for users and organizations and other entities
//! that have an identity. A cryptographic identitiy usually at least has a public-key-encryption
//! key-pair and a signing key-pair. The signing-key-pair signs the public-key-encryption public key
//! to create a binding between these. In protocols, the signing-key-pair's verifying key
//! fingerprint is included to bind to the identity.
//!
//! There are two types of identities, the `OtherIdentity` and the `SelfIdentity`.
//!
//! An `OtherIdentity` is used to represent the public-facing cryptographic identity of another
//! user or organization. It contains their signed public key and verifying key. The signed public
//! key is verified against the verifying key during construction to ensure the identity is valid.
//!
//! A `SelfIdentity` is used to represent the current user's cryptographic identity. It holds a
//! reference to a `KeyStoreContext` which provides access to the user's private keys.

use thiserror::Error;

use crate::{
    AsymmetricPublicCryptoKey, DeriveFingerprint, KeyFingerprint, KeyIds, SignedPublicKey,
    VerifyingKey, store::KeyStoreContext,
};

/// Errors that can occur when constructing an `OtherIdentity`.
#[derive(Debug, Error)]
pub enum OtherIdentityError {
    /// The signature on the signed public key is invalid.
    #[error("Signed public key verification failed")]
    SignedPublicKeyVerificationFailed,
}

/// Represents another user's or organization's cryptographic identity.
///
/// This struct contains the verified public key material of another user. The signed public key
/// is verified against the verifying key during construction, ensuring that the identity is
/// cryptographically valid before it can be used.
pub struct OtherIdentity {
    /// The signed public key, verified to be signed by the holder of the verifying key.
    #[allow(dead_code)]
    signed_public_key: SignedPublicKey,
    /// The verifying key used to verify signatures from this identity.
    verifying_key: VerifyingKey,
    /// The verified public encryption key, extracted from the signed public key.
    public_key: AsymmetricPublicCryptoKey,
}

impl OtherIdentity {
    /// Returns a reference to the signed public key.
    #[allow(dead_code)]
    pub(crate) fn signed_public_key(&self) -> &SignedPublicKey {
        &self.signed_public_key
    }

    /// Returns a reference to the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns a reference to the verified public encryption key.
    pub(crate) fn public_key(&self) -> &AsymmetricPublicCryptoKey {
        &self.public_key
    }
}

impl DeriveFingerprint for OtherIdentity {
    /// Derives the fingerprint from the verifying key of this identity.
    fn fingerprint(&self) -> crate::traits::key_fingerprint::KeyFingerprint {
        self.verifying_key.fingerprint()
    }
}

impl TryFrom<(SignedPublicKey, VerifyingKey)> for OtherIdentity {
    type Error = OtherIdentityError;

    /// Constructs an `OtherIdentity` from a signed public key and verifying key.
    ///
    /// This will verify that the signature on the signed public key is valid before
    /// constructing the identity. If the signature is invalid, an error is returned.
    fn try_from(
        (signed_public_key, verifying_key): (SignedPublicKey, VerifyingKey),
    ) -> Result<Self, Self::Error> {
        // Verify the signed public key and extract the public encryption key
        let public_key = signed_public_key
            .clone()
            .verify_and_unwrap(&verifying_key)
            .map_err(|_| OtherIdentityError::SignedPublicKeyVerificationFailed)?;

        Ok(OtherIdentity {
            signed_public_key,
            verifying_key,
            public_key,
        })
    }
}

/// Represents the current user's / organization's cryptographic identity.
///
/// This struct holds a reference to a `KeyStoreContext` which provides access to the user's /
/// organization's private keys for cryptographic operations such as signing and decryption.
pub struct SelfIdentity<'a, Ids: KeyIds> {
    /// Reference to the key store context containing the user's private keys.
    ctx: &'a KeyStoreContext<'a, Ids>,
    /// The key ID for the user's signing key.
    signing_key_id: Ids::Signing,
    /// The key ID for the user's asymmetric encryption key.
    asymmetric_key_id: Ids::Asymmetric,
}

/// Error indicating that a required key was not found in the key store.
pub struct KeyNotFoundError;

impl<'a, Ids: KeyIds> SelfIdentity<'a, Ids> {
    /// Creates a new `SelfIdentity` from a key store context and key IDs.
    pub fn new(
        ctx: &'a KeyStoreContext<'a, Ids>,
        signing_key_id: Ids::Signing,
        asymmetric_key_id: Ids::Asymmetric,
    ) -> Self {
        Self {
            ctx,
            signing_key_id,
            asymmetric_key_id,
        }
    }

    /// Returns a reference to the key store context.
    pub fn context(&self) -> &KeyStoreContext<'a, Ids> {
        self.ctx
    }

    /// Returns the signing key ID.
    pub fn signing_key_id(&self) -> Ids::Signing {
        self.signing_key_id
    }

    /// Returns the private encryption key ID.
    pub fn private_key_id(&self) -> Ids::Asymmetric {
        self.asymmetric_key_id
    }

    /// Derives the fingerprint from the signing key of this identity.
    pub fn fingerprint(&self) -> Result<KeyFingerprint, KeyNotFoundError> {
        let verifying_key = self
            .ctx
            .get_verifying_key(self.signing_key_id)
            .map_err(|_| KeyNotFoundError)?;
        Ok(verifying_key.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AsymmetricCryptoKey, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
        SignedPublicKeyMessage, SigningKey,
    };

    #[test]
    fn test_other_identity_valid_signature() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let verifying_key = signing_key.to_verifying_key();
        let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signed_public_key =
            SignedPublicKeyMessage::from_public_key(&private_key.to_public_key())
                .expect("Failed to create signed public key message")
                .sign(&signing_key)
                .expect("Failed to sign public key");

        let identity = OtherIdentity::try_from((signed_public_key, verifying_key));
        assert!(identity.is_ok());
    }

    #[test]
    fn test_other_identity_invalid_signature() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let wrong_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let wrong_verifying_key = wrong_signing_key.to_verifying_key();
        let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signed_public_key =
            SignedPublicKeyMessage::from_public_key(&private_key.to_public_key())
                .expect("Failed to create signed public key message")
                .sign(&signing_key)
                .expect("Failed to sign public key");

        // Using the wrong verifying key should fail
        let identity = OtherIdentity::try_from((signed_public_key, wrong_verifying_key));
        assert!(identity.is_err());
    }
}
