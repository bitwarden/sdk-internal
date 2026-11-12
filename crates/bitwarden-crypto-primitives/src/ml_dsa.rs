//! ML-DSA-44 signatures (FIPS 204).

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Seed length in bytes.
pub const SEED_LEN: usize = 32;

/// ML-DSA-44 signing key. Holds the seed and the expanded key; zeroized on drop.
#[derive(Clone)]
pub struct SigningKey(backend::ml_dsa::SigningKey);

impl zeroize::ZeroizeOnDrop for SigningKey where backend::ml_dsa::SigningKey: zeroize::ZeroizeOnDrop {}

impl SigningKey {
    /// Generates a fresh key.
    pub fn generate() -> Self {
        Self(backend::ml_dsa::SigningKey::generate())
    }

    /// Expands a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(backend::ml_dsa::SigningKey::from_seed(seed))
    }

    /// Returns the 32-byte seed.
    pub fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.0.seed()
    }

    /// Returns the matching verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Signs `msg` with hedged randomness and an empty context.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg)
    }
}

/// ML-DSA-44 verifying key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey(backend::ml_dsa::VerifyingKey);

impl VerifyingKey {
    /// Parses an encoded verifying key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        backend::ml_dsa::VerifyingKey::from_bytes(bytes).map(Self)
    }

    /// Returns the encoded verifying key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Verifies `sig` over `msg` with an empty context.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.0.verify(msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-DSA-44 encoded verifying key length (FIPS 204 Table 2).
    const PUBLIC_KEY_LEN: usize = 1312;
    /// ML-DSA-44 signature length (FIPS 204 Table 2).
    const SIGNATURE_LEN: usize = 2420;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate();
        let sig = key.sign(b"msg");
        assert_eq!(sig.len(), SIGNATURE_LEN);

        let vk = key.verifying_key();
        assert_eq!(vk.verify(b"msg", &sig), Ok(()));
        assert_eq!(vk.verify(b"other", &sig), Err(Error::InvalidSignature));
        assert_eq!(vk.verify(b"msg", &sig[..10]), Err(Error::InvalidSignature));
    }

    #[test]
    fn seed_is_deterministic() {
        let a = SigningKey::from_seed(&[3; SEED_LEN]);
        let b = SigningKey::from_seed(&a.seed());
        assert!(a.verifying_key() == b.verifying_key());

        let bytes = a.verifying_key().to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_LEN);
        assert!(VerifyingKey::from_bytes(&bytes).expect("valid") == a.verifying_key());
        assert_eq!(
            VerifyingKey::from_bytes(&bytes[1..]).err(),
            Some(Error::InvalidKey)
        );
    }
}
