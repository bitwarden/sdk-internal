use ::signature::SignerMut;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{ed25519, SigningKey, VerifyingKey};
use pkcs8::{der::Decode, DecodePrivateKey, EncodePrivateKey, PrivateKeyInfo};

use super::{signature, SignerImpl, VerifierImpl};
use crate::{error::Result, CryptoError, EncString, KeyDecryptable, SymmetricCryptoKey};

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

// impl Ed25519KeyPair {
//     fn verifier(&self) -> VerifyingKey {
//         let spki = STANDARD.decode(&self.verifier).unwrap();
//         let decoded_public_key: VerifyingKey =
//             pkcs8::DecodePublicKey::from_public_key_der(spki.as_slice()).unwrap();
//         decoded_public_key
//     }

//     fn signer(&self, key: &SymmetricCryptoKey) -> Result<SigningKey> {
//         let pkcs8_private_key: Vec<u8> = self.signer.decrypt_with_key(key).unwrap();
//         let pkcs8_private_key = pkcs8_private_key.as_slice();
//         let signing_key = SigningKey::from_pkcs8_der(pkcs8_private_key).unwrap();
//         Ok(signing_key)
//     }
// }

// pub(crate) fn make_key_pair(encapsulating_key: &SymmetricCryptoKey) -> Result<Ed25519KeyPair> {
//     let mut rng = rand::thread_rng();
//     let signing_key: SigningKey = SigningKey::generate(&mut rng);
//     let verifying_key: VerifyingKey = signing_key.verifying_key();
//     let pkcs8_private_key = &signing_key.to_pkcs8_der().unwrap();
//     let private_key_info = PrivateKeyInfo::from_der(pkcs8_private_key.as_bytes()).unwrap();
//     private_key_info.algorithm.oid == ed25519::pkcs8::ALGORITHM_OID;
//     let pkcs8_private_key = pkcs8_private_key.as_bytes();
//     let spki = pkcs8::EncodePublicKey::to_public_key_der(&verifying_key).unwrap();
//     let public_key_b64 = STANDARD.encode(spki.as_bytes());

//     let protected = EncString::encrypt_aes256_hmac(
//         pkcs8_private_key.as_ref(),
//         encapsulating_key
//             .mac_key
//             .as_ref()
//             .ok_or(CryptoError::InvalidMac)?,
//         &encapsulating_key.key,
//     )?;

//     Ok(Ed25519KeyPair {
//         verifier: public_key_b64,
//         signer: protected,
//     })
// }

// impl Verifier for VerifyingKey {
//     fn verify(&self, data: &[u8], signature: &signature::Signature) -> bool {
//         let signature_bytes: [u8; 64] = signature.data.clone().try_into().unwrap();
//         let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
//         self.verify_strict(data, &signature).is_ok()
//     }
// }

// impl Signer for SigningKey {
//     fn sign(&mut self, data: &[u8]) -> signature::Signature {
//         let res = self.sign(self, data);
//         signature::Signature::new(super::SignatureAlgorithm::Ed25519, res.data)
//     }
//     fn verifier(&self) -> impl Verifier;
// }

// #[cfg(test)]
// mod tests {
//     use crate::{
//         signing::ed25519::{make_key_pair, sign_ed25519, verify_ed25519},
//         SymmetricCryptoKey,
//     };

//     #[test]
//     fn test_make_key_pair_and_sign() {
//         let key = SymmetricCryptoKey::generate(rand::thread_rng());
//         let key_pair = make_key_pair(&key).unwrap();
//         let verifier = key_pair.verifier();
//         let mut signer = key_pair.signer(&key).unwrap();
//         let data = b"hello world";
//         let signature = sign_ed25519(&mut signer, data).unwrap();
//         assert!(verify_ed25519(&verifier, data, &signature));
//     }
// }
