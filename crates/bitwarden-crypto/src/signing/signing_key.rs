use std::pin::Pin;

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, CoseKey, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter},
};
use ed25519_dalek::Signer;

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
                    &mut rand::thread_rng(),
                ))),
            },
        }
    }

    pub(super) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
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
        }
    }

    /// Signs the given byte array with the signing key.
    /// This should not be used directly other than for generating namespace separated signatures or
    /// signed objects.
    pub(super) fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
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
}
