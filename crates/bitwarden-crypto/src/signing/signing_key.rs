use std::pin::Pin;

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, CoseKey, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{
        AkpKeyParameter, Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter,
    },
};
use ed25519_dalek::Signer;
use ml_dsa::{KeyGen as _, MlDsa65};
use rand::RngCore;

use super::{
    SignatureAlgorithm, ed25519_signing_key, key_id, mldsa65_signing_key,
    verifying_key::{RawVerifyingKey, VerifyingKey},
};
use crate::{
    CoseKeyBytes, CryptoKey,
    content_format::CoseKeyContentFormat,
    cose::CoseSerializable,
    error::{EncodingError, Result},
    keys::KeyId,
};

pub(crate) const ML_DSA_SEED_SIZE: usize = 32;

/// A `SigningKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
#[derive(Clone)]
enum RawSigningKey {
    Ed25519(Pin<Box<ed25519_dalek::SigningKey>>),
    MlDsa65 {
        /// The seed is what's stored when serializing
        seed: Pin<Box<[u8; ML_DSA_SEED_SIZE]>>,
        /// The expanded signing key is derived from the seed
        signing_key: Pin<Box<ml_dsa::SigningKey<MlDsa65>>>,
        /// The verifying key is also derived from the seed
        verifying_key: Pin<Box<ml_dsa::VerifyingKey<MlDsa65>>>,
    },
}

/// A signing key is a private key used for signing data. An associated `VerifyingKey` can be
/// derived from it.
#[derive(Clone)]
pub struct SigningKey {
    pub(super) id: KeyId,
    inner: RawSigningKey,
}

// Note that `SigningKey` already implements ZeroizeOnDrop, so we don't need to do anything
// We add this assertion to make sure that this is still true in the future
// For any new keys, this needs to be checked
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    assert_zeroize_on_drop::<ml_dsa::SigningKey<MlDsa65>>();
};
impl zeroize::ZeroizeOnDrop for SigningKey {}
impl CryptoKey for SigningKey {}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_suffix = match &self.inner {
            RawSigningKey::Ed25519(_) => "Ed25519",
            RawSigningKey::MlDsa65 { .. } => "MlDsa65",
        };
        let mut debug_struct = f.debug_struct(format!("SigningKey::{}", key_suffix).as_str());
        debug_struct.field("id", &self.id);
        #[cfg(feature = "dangerous-crypto-debug")]
        match &self.inner {
            RawSigningKey::Ed25519(key) => debug_struct.field("key", &hex::encode(key.to_bytes())),
            RawSigningKey::MlDsa65 { seed, .. } => {
                debug_struct.field("seed", &hex::encode(*seed.as_ref()))
            }
        };
        debug_struct.finish()
    }
}

impl SigningKey {
    /// Makes a new signing key for the given signature scheme.
    pub fn make(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => SigningKey {
                id: KeyId::make(),
                inner: RawSigningKey::Ed25519(Box::pin(ed25519_dalek::SigningKey::generate(
                    &mut rand::thread_rng(),
                ))),
            },
            SignatureAlgorithm::MlDsa65 => {
                let mut seed = [0u8; ML_DSA_SEED_SIZE];
                rand::thread_rng().fill_bytes(&mut seed);
                let key_pair = MlDsa65::key_gen_internal(&seed.into());
                SigningKey {
                    id: KeyId::make(),
                    inner: RawSigningKey::MlDsa65 {
                        seed: Box::pin(seed),
                        signing_key: Box::pin(key_pair.signing_key().clone()),
                        verifying_key: Box::pin(key_pair.verifying_key().clone()),
                    },
                }
            }
        }
    }

    pub(super) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
            RawSigningKey::MlDsa65 { .. } => Algorithm::ML_DSA_65,
        }
    }

    /// Derives the verifying key from the signing key. The key id is the same for the signing and
    /// verifying key, since they are a pair.
    pub fn to_verifying_key(&self) -> VerifyingKey {
        match &self.inner {
            RawSigningKey::Ed25519(key) => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::Ed25519(key.verifying_key()),
            },
            RawSigningKey::MlDsa65 { verifying_key, .. } => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::MlDsa65(verifying_key.clone()),
            },
        }
    }

    /// Signs the given byte array with the signing key.
    /// This should not be used directly other than for generating namespace separated signatures or
    /// signed objects.
    pub(super) fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
            RawSigningKey::MlDsa65 { signing_key, .. } => signing_key
                .sign_randomized(data, &[], &mut rand::thread_rng())
                .expect("ML-DSA signing should not fail with empty context")
                .encode()
                .as_slice()
                .to_vec(),
        }
    }
}

impl CoseSerializable<CoseKeyContentFormat> for SigningKey {
    /// Serializes the signing key to a COSE-formatted byte array.
    fn to_cose(&self) -> CoseKeyBytes {
        match &self.inner {
            RawSigningKey::Ed25519(key) => {
                coset::CoseKeyBuilder::new_okp_key()
                    .key_id((&self.id).into())
                    .algorithm(Algorithm::EdDSA)
                    .param(
                        OkpKeyParameter::D.to_i64(), // Signing key
                        Value::Bytes(key.to_bytes().into()),
                    )
                    .param(
                        OkpKeyParameter::Crv.to_i64(), // Elliptic curve identifier
                        Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                    )
                    .add_key_op(KeyOperation::Sign)
                    .add_key_op(KeyOperation::Verify)
                    .build()
                    .to_vec()
                    .expect("Signing key is always serializable")
                    .into()
            }
            RawSigningKey::MlDsa65 {
                seed,
                verifying_key,
                ..
            } => {
                // https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
                let key = CoseKey {
                    key_id: (&self.id).into(),
                    kty: coset::RegisteredLabel::Assigned(KeyType::AKP),
                    alg: Some(coset::RegisteredLabelWithPrivate::Assigned(
                        Algorithm::ML_DSA_65,
                    )),
                    key_ops: vec![coset::RegisteredLabel::Assigned(KeyOperation::Sign)]
                        .into_iter()
                        .collect(),
                    params: vec![
                        (
                            coset::Label::Int(AkpKeyParameter::Priv.to_i64()),
                            Value::Bytes(seed.to_vec()),
                        ),
                        (
                            coset::Label::Int(AkpKeyParameter::Pub.to_i64()),
                            Value::Bytes(verifying_key.encode().to_vec()),
                        ),
                    ],
                    ..Default::default()
                };
                key.to_vec()
                    .expect("Signing key is always serializable")
                    .into()
            }
        }
    }

    /// Deserializes a COSE-formatted byte array into a signing key.
    fn from_cose(bytes: &CoseKeyBytes) -> Result<Self, EncodingError> {
        let cose_key =
            CoseKey::from_slice(bytes.as_ref()).map_err(|_| EncodingError::InvalidCoseEncoding)?;

        match (&cose_key.alg, &cose_key.kty) {
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA)),
                RegisteredLabel::Assigned(KeyType::OKP),
            ) => Ok(SigningKey {
                id: key_id(&cose_key)?,
                inner: RawSigningKey::Ed25519(Box::pin(ed25519_signing_key(&cose_key)?)),
            }),
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ML_DSA_65)),
                RegisteredLabel::Assigned(KeyType::AKP),
            ) => {
                let seed = mldsa65_signing_key(&cose_key)?;
                let key_pair = MlDsa65::key_gen_internal(&seed.into());
                let sk = key_pair.signing_key().clone();
                let vk = key_pair.verifying_key().clone();
                Ok(SigningKey {
                    id: key_id(&cose_key)?,
                    inner: RawSigningKey::MlDsa65 {
                        seed: Box::pin(seed),
                        signing_key: Box::pin(sk),
                        verifying_key: Box::pin(vk),
                    },
                })
            }
            _ => Err(EncodingError::UnsupportedValue(
                "COSE key type or algorithm",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_debug() {
        let key = SigningKey::make(SignatureAlgorithm::Ed25519);
        println!("{:?}", key);
        let verifying_key = key.to_verifying_key();
        println!("{:?}", verifying_key);

        let key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        println!("{:?}", key);
        let verifying_key = key.to_verifying_key();
        println!("{:?}", verifying_key);
    }

    #[test]
    fn test_cose_roundtrip_encode_signing() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let cose = signing_key.to_cose();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(signing_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_sign_rountrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let signature = signing_key.sign_raw("Test message".as_bytes());
        let verifying_key = signing_key.to_verifying_key();
        assert!(
            verifying_key
                .verify_raw(&signature, "Test message".as_bytes())
                .is_ok()
        );
    }

    #[test]
    #[ignore = "Run manually to generate ML-DSA-65 test vectors"]
    fn generate_test_vectors_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let verifying_key = signing_key.to_verifying_key();
        let raw_signature = signing_key.sign_raw(b"Test message");

        println!(
            "const MLDSA65_SIGNING_KEY: &str = \"{}\";",
            hex::encode(signing_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA65_VERIFYING_KEY: &str = \"{}\";",
            hex::encode(verifying_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA65_SIGNED_DATA_RAW: &str = \"{}\";",
            hex::encode(raw_signature.as_slice())
        );
    }

    #[test]
    fn test_cose_roundtrip_encode_signing_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let cose = signing_key.to_cose();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(signing_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_sign_roundtrip_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let signature = signing_key.sign_raw(b"Test message");
        let verifying_key = signing_key.to_verifying_key();
        assert!(
            verifying_key
                .verify_raw(&signature, b"Test message")
                .is_ok()
        );
    }
}
