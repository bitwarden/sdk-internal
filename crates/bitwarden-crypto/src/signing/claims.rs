use serde::{Deserialize, Serialize};

use crate::{AsymmetricPublicCryptoKey, CryptoError, FingerprintableKey, PublicKeyFingerprint, SignedObject, SigningKey, VerifyingKey};
use crate::keys::Fingerprintable;

use super::SigningNamespace;


#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PublicKeyOwnershipClaim {
    pub fingerprint: PublicKeyFingerprint,
}

impl PublicKeyOwnershipClaim {
    pub fn for_public_key(
        public_key: &impl FingerprintableKey,
    ) -> Self {
        Self {
            fingerprint: public_key.fingerprint(),
        }
    }
}

/// A signed public key ownership claim represents a claim by a signing key that it owns
/// a specific public encryption key. This is used to tie the cryptographic identity (signing)
/// to the encryption receiving identity (asymmetric encryption key).
pub struct SignedPublicKeyOwnershipClaim(Vec<u8>);

impl SignedPublicKeyOwnershipClaim {
    pub fn make_claim_with_key(
        public_key: &AsymmetricPublicCryptoKey,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let claim = PublicKeyOwnershipClaim::for_public_key(public_key);
        let mut claim_bytes = vec![];
        ciborium::into_writer(&claim, &mut claim_bytes).map_err(|_| {
            CryptoError::InvalidEncoding
        })?;
        let signature = signing_key.sign(&SigningNamespace::PublicKeyOwnershipClaim, &claim_bytes)?;
        Ok(Self(signature.to_cose()?))
    }

    pub fn verify_claim(
        &self,
        public_key: &AsymmetricPublicCryptoKey,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, CryptoError> {
        let signed_object = SignedObject::from_cose(&self.0)?;
        let serialized_claim = verifying_key.get_verified_payload(&SigningNamespace::PublicKeyOwnershipClaim, &signed_object)?; 
        let claim: PublicKeyOwnershipClaim = ciborium::de::from_reader(&serialized_claim[..]).map_err(|_| {
            CryptoError::InvalidEncoding
        })?;
        Ok(public_key.verify_fingerprint(&claim.fingerprint))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(bytes.to_vec()))
    }
}