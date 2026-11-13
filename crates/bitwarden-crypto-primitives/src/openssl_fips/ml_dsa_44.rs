use ::openssl::{
    pkey::{KeyType, PKey, Private, Public},
    sign::{Signer, Verifier},
};
use zeroize::Zeroizing;

use super::random::fill_bytes;
use crate::{Error, ml_dsa_44::SEED_LEN};

/// Encoded ML-DSA-44 verifying key length (FIPS 204 Table 2).
const PUBLIC_KEY_LEN: usize = 1312;

/// ML-DSA-44 key built from its seed, so OpenSSL can export the seed again.
#[derive(Clone)]
pub(crate) struct SigningKey(PKey<Private>);

// OpenSSL frees the seed and expanded key with `OPENSSL_clear_free`.
impl zeroize::ZeroizeOnDrop for SigningKey {}

impl SigningKey {
    pub(crate) fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        fill_bytes(seed.as_mut_slice());
        Self::from_seed(&seed)
    }

    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(
            PKey::private_key_from_seed(None, KeyType::ML_DSA_44, None, seed)
                .expect("every 32-byte string is an ML-DSA seed"),
        )
    }

    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let len = self
            .0
            .seed_into(seed.as_mut_slice())
            .expect("keys built from a seed keep it");
        assert_eq!(len, SEED_LEN, "ML-DSA seed is 32 bytes");
        seed
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        let raw = self
            .0
            .raw_public_key()
            .expect("ML-DSA keys export their encoded public key");
        VerifyingKey::from_bytes(&raw).expect("a derived public key is valid")
    }

    /// Hedged signing with an empty context: OpenSSL's ML-DSA default is randomized `rnd` from
    /// its DRBG and an empty context string.
    pub(crate) fn sign(&self, msg: &[u8]) -> Vec<u8> {
        const INFALLIBLE: &str = "ML-DSA signing of in-memory data does not fail";

        let mut signer = Signer::new_without_digest(&self.0).expect(INFALLIBLE);
        signer.sign_oneshot_to_vec(msg).expect(INFALLIBLE)
    }
}

#[derive(Clone)]
pub(crate) struct VerifyingKey(PKey<Public>);

/// Public data: compare keys.
impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_eq(&other.0)
    }
}

impl Eq for VerifyingKey {}

impl VerifyingKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidKey);
        }

        PKey::public_key_from_raw_bytes_ex(None, KeyType::ML_DSA_44, None, bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0
            .raw_public_key()
            .expect("ML-DSA keys export their encoded public key")
    }

    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let mut verifier =
            Verifier::new_without_digest(&self.0).map_err(|_| Error::InvalidSignature)?;
        match verifier.verify_oneshot(sig, msg) {
            Ok(true) => Ok(()),
            _ => Err(Error::InvalidSignature),
        }
    }
}
