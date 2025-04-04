
use coset::{iana, CborSerializable};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;

use crate::error::Result;

struct Ed25519SigningKey {
    key: ed25519_dalek::SigningKey,
}

struct Ed25519VerifyingKey {
    key: ed25519_dalek::VerifyingKey,
}

pub enum SigningCryptoKey {
    Ed25519(Ed25519SigningKey),
}

impl SigningCryptoKey {
    pub fn generate() -> Result<Self> {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Ok(SigningCryptoKey::Ed25519(Ed25519SigningKey {
            key: signing_key,
        }))
    }

    pub fn to_cose(&self) -> Result<Vec<u8>> {
        match self {
            SigningCryptoKey::Ed25519(key) => {
                let cose = coset::CoseKeyBuilder::new_okp_key()
                    .add_key_op(iana::KeyOperation::Sign)
                    .add_key_op(iana::KeyOperation::Verify)
                    .build();
                cose.to_vec().map_err(|_| crate::error::CryptoError::InvalidKey)
            }
        }
    }

    pub(crate) fn sign(&self, namespace: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .text_value("namespace".to_string(), ciborium::Value::Bytes(namespace.to_vec()))
            .build();
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(data, &[], |pt| self.sign_raw(pt).unwrap())
            .build();
        let sign1_data = sign1.to_vec().unwrap();

        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
        let sign1 = coset::CoseSign1::from_slice(&sign1_data).unwrap();
        Ok(sign1.to_vec().unwrap())
    }
    
    fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SigningCryptoKey::Ed25519(key) => {
                Ok(key.key.sign(data).to_vec())
            }
        }
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        match self {
            SigningCryptoKey::Ed25519(key) => {
                VerifyingKey::Ed25519(Ed25519VerifyingKey {
                    key: key.key.verifying_key(),
                })
            }
        }
    }
}

pub enum VerifyingKey {
    Ed25519(Ed25519VerifyingKey),
}

impl VerifyingKey {
    pub fn to_cose(&self) -> Result<Vec<u8>> {
        match self {
            VerifyingKey::Ed25519(key) => {
                let cose = coset::CoseKeyBuilder::new_okp_key()
                    .add_key_op(iana::KeyOperation::Sign)
                    .add_key_op(iana::KeyOperation::Verify)
                    .build();
                cose.to_vec().map_err(|_| crate::error::CryptoError::InvalidKey)
            }
        }
    }

    fn verify(&self, namespace: &[u8], signature: &[u8], data: &[u8]) -> bool {
        let sign1 = coset::CoseSign1::from_slice(&signature).unwrap();
        let result = sign1.verify_detached_signature(data, &[], |sig, data| self.verify_raw(sig, data));
        return result.is_ok();
    }

    fn verify_raw(&self, signature: &[u8], data: &[u8]) -> Result<()> {
        match self {
            VerifyingKey::Ed25519(key) => {
                let sig = Signature::from_bytes(signature.try_into().map_err(|_| crate::error::CryptoError::InvalidSignature)?);
                key.key.verify_strict(data, &sig)
                    .map_err(|_| crate::error::CryptoError::InvalidSignature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key() {
        let signing_key = SigningCryptoKey::generate().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Hello, world!";
        let namespace = b"namespace";

        let signature = signing_key.sign(namespace, data).unwrap();
        assert!(verifying_key.verify(namespace, &signature, data));
    }
}