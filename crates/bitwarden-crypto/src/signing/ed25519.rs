use ::signature::SignerMut;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};

use super::{signature, SignerImpl, VerifierImpl};
use crate::{error::Result, CryptoError};

#[derive(Clone)]
pub(crate) struct Ed25519Verifier {
    inner: VerifyingKey,
}

impl VerifierImpl for Ed25519Verifier {
    fn verify(&self, data: &[u8], signature: &signature::Signature) -> bool {
        let signature_bytes: [u8; 64] = signature.data.clone().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        self.inner.verify_strict(data, &signature).is_ok()
    }
}

impl Ed25519Verifier {
    pub(crate) fn from_der(data: &[u8]) -> Result<Self> {
        let key_bytes: [u8; 32] = data.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            inner: verifying_key,
        })
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[derive(Clone)]
pub(crate) struct Ed25519Signer {
    inner: SigningKey,
}

impl SignerImpl<Ed25519Verifier> for Ed25519Signer {
    fn sign(&mut self, data: &[u8]) -> signature::Signature {
        let res = self.inner.sign(data);
        signature::Signature::new(super::SignatureAlgorithm::Ed25519, res.to_bytes().to_vec())
    }

    fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            inner: self.inner.verifying_key(),
        }
    }

    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        Self {
            inner: SigningKey::generate(rng),
        }
    }
}

impl Ed25519Signer {
    pub(crate) fn from_der(data: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_der(data).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner: signing_key })
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        self.inner.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }
}
