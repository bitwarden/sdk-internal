use ml_dsa::{
    B32, EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, Signature, signature::Verifier,
};
use zeroize::Zeroizing;

use super::random::fill_bytes;
use crate::{Error, ml_dsa::SEED_LEN, random::SystemRng};

/// Seed and expanded key. The seed is kept because it is the serialized form.
#[derive(Clone)]
pub(crate) struct SigningKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    key: Box<ExpandedSigningKey<MlDsa44>>,
}

// Both fields wipe themselves on drop.
impl zeroize::ZeroizeOnDrop for SigningKey {}
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ExpandedSigningKey<MlDsa44>>();
};

impl SigningKey {
    pub(crate) fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_bytes(seed.as_mut_slice());
        Self::from_seed(&seed)
    }

    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        // Fill the array in place so no unzeroized copy of the seed is left on the stack.
        let mut b32 = Zeroizing::new(B32::default());
        b32.copy_from_slice(seed);
        Self {
            seed: Zeroizing::new(*seed),
            key: Box::new(ExpandedSigningKey::<MlDsa44>::from_seed(&b32)),
        }
    }

    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.seed.clone()
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(Box::new(self.key.verifying_key()))
    }

    /// Hedged signing with an empty context.
    pub(crate) fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key
            .sign_randomized(msg, &[], &mut SystemRng)
            .expect("Empty ML-DSA context must be accepted")
            .encode()
            .to_vec()
    }
}

#[derive(Clone)]
pub(crate) struct VerifyingKey(Box<ml_dsa::VerifyingKey<MlDsa44>>);

/// Public data: compare encodings.
impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.encode() == other.0.encode()
    }
}

impl Eq for VerifyingKey {}

impl VerifyingKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded =
            EncodedVerifyingKey::<MlDsa44>::try_from(bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Self(Box::new(ml_dsa::VerifyingKey::<MlDsa44>::decode(
            &encoded,
        ))))
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let sig = Signature::<MlDsa44>::try_from(sig).map_err(|_| Error::InvalidSignature)?;
        self.0
            .verify(msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}
