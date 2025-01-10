mod ed25519;
pub mod signature;

#[derive(Debug, Clone, PartialEq)]
pub enum SignatureAlgorithm {
    Ed25519,
}

enum SignatureImpl {
    Ed25519(ed25519::Ed25519Signer),
}

enum VerifyImpl {
    Ed25519(ed25519::Ed25519Verifier),
}

struct Signer {
    impl_: SignatureImpl,
}

struct Verifier {
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
