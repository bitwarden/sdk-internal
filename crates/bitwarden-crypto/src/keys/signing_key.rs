use std::pin::Pin;

use super::key_encryptable::CryptoKey;
use crate::{
    error::Result,
    signing::{SignatureAlgorithm, Signer, Verifier},
};

pub trait Verifiable {
    fn verifier(&self) -> VerifyingCryptoKey;
}

pub struct VerifyingCryptoKey {
    verifier: Verifier,
}

impl VerifyingCryptoKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            verifier: Verifier::from_spki_der(der)?,
        })
    }

    pub fn to_spki_der(&self) -> Vec<u8> {
        self.verifier.to_spki_der()
    }
}

#[derive(Clone)]
pub struct SigningCryptoKey {
    pub(crate) signing_key: Pin<Box<Signer>>,
}

const _: () = {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    fn assert_all() {
        assert_zeroize_on_drop::<Signer>();
    }
};

impl zeroize::ZeroizeOnDrop for SigningCryptoKey {}

impl SigningCryptoKey {
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let algorithm = SignatureAlgorithm::Ed25519;
        Self {
            signing_key: Box::pin(Signer::generate(rng, &algorithm)),
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            signing_key: Box::pin(Signer::from_pkcs8_der(der)?),
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.to_pkcs8_der())
    }
}

impl Verifiable for SigningCryptoKey {
    fn verifier(&self) -> VerifyingCryptoKey {
        VerifyingCryptoKey {
            verifier: self.signing_key.verifier(),
        }
    }
}

impl CryptoKey for SigningCryptoKey {}

// We manually implement these to make sure we don't print any sensitive data
impl std::fmt::Debug for SigningCryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCryptoKey").finish()
    }
}
