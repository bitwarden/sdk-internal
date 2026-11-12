use ed25519_dalek::Signer;
use zeroize::Zeroizing;

use super::random::SystemRng;
use crate::Error;

#[derive(Clone)]
pub(crate) struct SigningKey(ed25519_dalek::SigningKey);

// The wrapped key wipes itself on drop.
impl zeroize::ZeroizeOnDrop for SigningKey {}
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
};

impl SigningKey {
    pub(crate) fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut SystemRng))
    }

    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub(crate) fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Strict verification: rejects small-order keys and non-canonical signatures.
    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(sig);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}
