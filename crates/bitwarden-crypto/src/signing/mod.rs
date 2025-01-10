use pkcs8::{der::Decode, PrivateKeyInfo, SubjectPublicKeyInfoRef};
use zeroize::ZeroizeOnDrop;

use crate::{key_hash::KeyHash, signing_key::SigningCryptoKey, CryptoError};

mod ed25519;
pub mod signature;

#[derive(Debug, Clone, PartialEq)]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Clone)]
enum SignatureImpl {
    Ed25519(ed25519::Ed25519Signer),
}

#[derive(Clone)]
enum VerifyImpl {
    Ed25519(ed25519::Ed25519Verifier),
}

#[derive(Clone)]
pub(crate) struct Signer {
    impl_: SignatureImpl,
}

impl ZeroizeOnDrop for Signer {}

#[derive(Clone)]
pub(crate) struct Verifier {
    impl_: VerifyImpl,
}

impl Signer {
    pub(crate) fn generate<R: rand::CryptoRng + rand::RngCore>(
        rng: &mut R,
        algorithm: &SignatureAlgorithm,
    ) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let signing_key = ed25519::Ed25519Signer::generate(rng);
                Signer {
                    impl_: SignatureImpl::Ed25519(signing_key),
                }
            }
        }
    }

    pub(crate) fn sign(&mut self, data: &[u8]) -> signature::Signature {
        match &mut self.impl_ {
            SignatureImpl::Ed25519(signer) => signer.sign(data),
        }
    }

    pub(crate) fn verifier(&self) -> Verifier {
        match &self.impl_ {
            SignatureImpl::Ed25519(signer) => Verifier {
                impl_: VerifyImpl::Ed25519(signer.verifier()),
            },
        }
    }

    pub(crate) fn from_pkcs8_der(data: &[u8]) -> Result<Self, CryptoError> {
        let private_key_info =
            PrivateKeyInfo::from_der(data).map_err(|_| CryptoError::KeyDecrypt)?;
        match private_key_info.algorithm.oid {
            ed25519_dalek::ed25519::pkcs8::ALGORITHM_OID => Ok(Signer {
                impl_: SignatureImpl::Ed25519(ed25519::Ed25519Signer::from_der(data)?),
            }),
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub(crate) fn to_pkcs8_der(&self) -> Vec<u8> {
        match &self.impl_ {
            SignatureImpl::Ed25519(signer) => signer.to_der(),
        }
    }
}

impl Verifier {
    pub(crate) fn verify(&self, data: &[u8], signature: &signature::Signature) -> bool {
        match &self.impl_ {
            VerifyImpl::Ed25519(verifier) => {
                if !signature.algorithm().eq(&SignatureAlgorithm::Ed25519) {
                    return false;
                }
                verifier.verify(data, signature)
            }
        }
    }

    pub(crate) fn from_spki_der(data: &[u8]) -> Result<Self, CryptoError> {
        let public_key_info =
            SubjectPublicKeyInfoRef::from_der(data).map_err(|_| CryptoError::InvalidKey)?;
        match public_key_info.algorithm.oid {
            ed25519_dalek::ed25519::pkcs8::ALGORITHM_OID => Ok(Verifier {
                impl_: VerifyImpl::Ed25519(ed25519::Ed25519Verifier::from_der(data)?),
            }),
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub(crate) fn to_spki_der(&self) -> Vec<u8> {
        match &self.impl_ {
            VerifyImpl::Ed25519(verifier) => verifier.to_der(),
        }
    }
}

impl SignatureAlgorithm {
    pub fn from_str(algorithm: &str) -> Option<Self> {
        match algorithm {
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Self::Ed25519 => "ed25519".to_string(),
        }
    }
}

trait VerifierImpl {
    fn verify(&self, data: &[u8], signature: &signature::Signature) -> bool;
}

trait SignerImpl<V: VerifierImpl> {
    fn sign(&mut self, data: &[u8]) -> signature::Signature;
    fn verifier(&self) -> V;
    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self;
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_sign_verify() {
        let mut rng = OsRng;
        let mut signer = Signer::generate(&mut rng, &SignatureAlgorithm::Ed25519);
        let verifier = signer.verifier();
        let data = b"hello world";
        let signature = signer.sign(data);
        assert!(verifier.verify(data, &signature));
    }
}
