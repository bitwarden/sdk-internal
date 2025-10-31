use std::pin::Pin;

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, CoseKey, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter},
};
use ed25519_dalek::Signer;
#[cfg(feature = "post-quantum-crypto")]
use ml_dsa::{B32, KeyGen, MlDsa65};
use rand_core::RngCore;

use super::{
    SignatureAlgorithm, ed25519_signing_key, key_id,
    verifying_key::{RawVerifyingKey, VerifyingKey},
};
use crate::{
    CoseKeyBytes, CryptoKey,
    content_format::CoseKeyContentFormat,
    cose::CoseSerializable,
    error::{EncodingError, Result},
    keys::KeyId,
};

/// A `SigningKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
#[derive(Clone)]
enum RawSigningKey {
    Ed25519(Pin<Box<ed25519_dalek::SigningKey>>),
    #[cfg(feature = "post-quantum-crypto")]
    // ML-DSA has two representations of the private key - the seed, and the expanded signing key.
    // We store the seed here as it is always possible to go from seed to expanded private key + public key.
    // other transitions are not possible. Further, the seed is used in cose to represent the private key,
    // and cose does not allow storing the expanded signing key.
    MLDsa65(Pin<Box<B32>>),
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
};
impl zeroize::ZeroizeOnDrop for SigningKey {}
impl CryptoKey for SigningKey {}

impl SigningKey {
    /// Makes a new signing key for the given signature scheme.
    pub fn make(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => SigningKey {
                id: KeyId::make(),
                inner: RawSigningKey::Ed25519(Box::pin(ed25519_dalek::SigningKey::generate(
                    &mut rand::rng(),
                ))),
            },
            #[cfg(feature = "post-quantum-crypto")]
            SignatureAlgorithm::MLDsa65 => {
                let mut seed = [0u8; 32];
                rand::rng().fill_bytes(&mut seed);
                SigningKey {
                    id: KeyId::make(),
                    inner: RawSigningKey::MLDsa65(Box::pin(ml_dsa::B32::from(seed))),
                }
            }
        }
    }

    pub(super) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
            #[cfg(feature = "post-quantum-crypto")]
            RawSigningKey::MLDsa65(_) => Algorithm::ML_DSA_65,
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
            #[cfg(feature = "post-quantum-crypto")]
            RawSigningKey::MLDsa65(seed) => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::MlDsa65(
                    MlDsa65::key_gen_internal(seed).verifying_key().to_owned(),
                ),
            },
        }
    }

    /// Signs the given byte array with the signing key.
    /// This should not be used directly other than for generating namespace separated signatures or
    /// signed objects.
    pub(super) fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
            #[cfg(feature = "post-quantum-crypto")]
            RawSigningKey::MLDsa65(seed) => MlDsa65::key_gen_internal(seed)
                // ctx is empty, the CTX is provided otherwise in the namespace of the signature message, to abstract
                // away from the specific signature scheme
                // note: TODO: replace with sind randomized when crates don't collide
                .signing_key()
                .sign_deterministic(data, &[])
                .expect("signing should not fail")
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
            #[cfg(feature = "post-quantum-crypto")]
            RawSigningKey::MLDsa65(seed) => {
                use crate::KEY_ID_SIZE;
                use coset::{Label, iana::AkpKeyParameter};
                use std::collections::BTreeSet;

                CoseKey {
                    kty: RegisteredLabel::Assigned(KeyType::AKP),
                    key_id: Vec::from(Into::<[u8; KEY_ID_SIZE]>::into(self.id.clone())),
                    alg: Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ML_DSA_65)),
                    base_iv: vec![],
                    key_ops: BTreeSet::from([
                        RegisteredLabel::Assigned(KeyOperation::Sign),
                        RegisteredLabel::Assigned(KeyOperation::Verify),
                    ]),
                    params: vec![
                        (
                            Label::Int(AkpKeyParameter::Priv.to_i64()),
                            Value::Bytes(seed.as_ref().to_vec()),
                        ),
                        (
                            Label::Int(AkpKeyParameter::Pub.to_i64()),
                            Value::Bytes(
                                MlDsa65::key_gen_internal(seed)
                                    .verifying_key()
                                    .encode()
                                    .as_slice()
                                    .to_vec(),
                            ),
                        ),
                    ],
                }
                .to_vec()
                .expect("encoding should work")
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
    fn test_sign_rountrip_mldsa65() {
        #[cfg(feature = "post-quantum-crypto")]
        {
            let signing_key = SigningKey::make(SignatureAlgorithm::MLDsa65);
            let signature = signing_key.sign_raw("Test message".as_bytes());
            let verifying_key = signing_key.to_verifying_key();
            assert!(
                verifying_key
                    .verify_raw(&signature, "Test message".as_bytes())
                    .is_ok()
            );
        }
    }
}
