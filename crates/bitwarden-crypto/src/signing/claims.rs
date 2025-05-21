use super::SigningNamespace;
use crate::{
    keys::Fingerprintable, AsymmetricPublicCryptoKey, CryptoError, FingerprintableKey,
    PublicKeyFingerprint, SignedObject, SigningKey, VerifyingKey,
};

/// The non-serialized version of `SignedPublicKeyOwnershipClaim`
pub(crate) struct PublicKeyOwnershipClaim {
    pub(crate) fingerprint: PublicKeyFingerprint,
}

impl PublicKeyOwnershipClaim {
    pub(crate) fn for_public_key(public_key: &impl FingerprintableKey) -> Self {
        Self {
            fingerprint: public_key.fingerprint(),
        }
    }
}

/// A user or org shall only have one long-term cryptographic identity. This is the signing key. A
/// user also needs to receive messages asymmetrically shared to them. Thus, an object tying the
/// signing key to the asymmetric encryption public key is needed. A signed public key ownership
/// claim represents a claim by a signing key that it owns a specific public encryption key. This is
/// used to tie the cryptographic identity (signing) to the encryption receiving identity
/// (asymmetric encryption key).
///
/// 1. Initially, Alice knows Bob's cryptographic identity (verifying key).
/// 2. Alice wants to send a message to Bob using his public encryption key.
/// 3. Alice gets Bob's public encryption key from the server, along with the
///    [`SignedPublicKeyOwnershipClaim`].
/// 4. Alice verifies the claim using Bob's verifying key that she trusts.
/// ```
/// use rand::rngs::OsRng;
/// use bitwarden_crypto::{AsymmetricCryptoKey, CryptoError, SigningKey, VerifyingKey, SignedPublicKeyOwnershipClaim, SignatureAlgorithm};
///
/// // Initial setup
/// let bob_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
/// let bob_verifying_key = bob_signing_key.to_verifying_key();
/// let bob_public_key = AsymmetricCryptoKey::generate(&mut OsRng).to_public_key();
///
/// // Alice trusts Bob's verifying key - this becomes Bob's cryptographic identity.
/// let bob_claim = SignedPublicKeyOwnershipClaim::make_claim_with_key(&bob_public_key, &bob_signing_key).unwrap();
/// // Alice downloads Bob's public key from the server.
/// // Alice verifies the claim using Bob's verifying key.
/// assert!(bob_claim.verify_claim(&bob_public_key, &bob_verifying_key).unwrap());
/// // Alice can now send a message to Bob using his public encryption key.
pub struct SignedPublicKeyOwnershipClaim(Vec<u8>);

impl SignedPublicKeyOwnershipClaim {
    /// Creates a new `SignedPublicKeyOwnershipClaim` for the provided public key and signing key.
    pub fn make_claim_with_key(
        public_key: &AsymmetricPublicCryptoKey,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let claim = PublicKeyOwnershipClaim::for_public_key(public_key);
        let signature = signing_key.sign(&claim, &SigningNamespace::PublicKeyOwnershipClaim)?;
        Ok(Self(signature.to_cose()?))
    }

    /// Verifies the signed claim using the provided public key and verifying key.
    pub fn verify_claim(
        &self,
        public_key: &AsymmetricPublicCryptoKey,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, CryptoError> {
        let signed_object = SignedObject::from_cose(&self.0)?;
        let claim: PublicKeyOwnershipClaim = verifying_key
            .get_verified_payload(&signed_object, &SigningNamespace::PublicKeyOwnershipClaim)?;
        Ok(public_key.verify_fingerprint(&claim.fingerprint))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::{AsymmetricCryptoKey, SignatureAlgorithm};

    #[test]
    fn test_public_key_ownership_claim() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let public_key = AsymmetricCryptoKey::generate(&mut OsRng).to_public_key();
        let claim =
            SignedPublicKeyOwnershipClaim::make_claim_with_key(&public_key, &signing_key).unwrap();
        assert!(claim.verify_claim(&public_key, &verifying_key).unwrap());
    }
}
