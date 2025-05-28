use ciborium::{value::Integer, Value};
use coset::{
    iana::{Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter},
    CborSerializable, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate,
};
use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use zeroize::ZeroizeOnDrop;

use super::{
    verifying_key::{RawVerifyingKey, VerifyingKey},
    SignatureAlgorithm,
};
use crate::{
    cose::CoseSerializable, error::Result, keys::KeyId, CryptoError, CryptoKey, KEY_ID_SIZE,
};

/// A `SigningKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
enum RawSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
}

/// A signing key is a private key used for signing data. An associated `VerifyingKey` can be
/// derived from it.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey {
    pub(super) id: KeyId,
    inner: RawSigningKey,
}

impl CryptoKey for SigningKey {}

impl SigningKey {
    /// Makes a new signing key for the given signature scheme.
    pub fn make(algorithm: SignatureAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => Ok(SigningKey {
                id: KeyId::make(),
                inner: RawSigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng)),
            }),
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
    /// This should never be used directly by anything other than the second layer defined in
    /// [super::message].
    pub fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
        }
    }
}

impl CoseSerializable for SigningKey {
    /// Serializes the signing key to a COSE-formatted byte array.
    fn to_cose(&self) -> Result<Vec<u8>> {
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
                    .map_err(|_| CryptoError::InvalidKey)
            }
        }
    }

    /// Deserializes a COSE-formatted byte array into a signing key.
    fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_key = CoseKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;

        let Some(algorithm) = cose_key.alg else {
            return Err(CryptoError::InvalidKey);
        };
        let key_id: [u8; KEY_ID_SIZE] = cose_key
            .key_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let key_id: KeyId = key_id.into();
        match (cose_key.kty, algorithm) {
            (kty, alg)
                if kty == RegisteredLabel::Assigned(KeyType::OKP)
                    && alg == RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA) =>
            {
                // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
                let (mut crv, mut d) = (None, None);
                for (key, value) in &cose_key.params {
                    if let Label::Int(i) = key {
                        let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
                        match key {
                            OkpKeyParameter::Crv => {
                                crv.replace(value);
                            }
                            OkpKeyParameter::D => {
                                d.replace(value);
                            }
                            _ => (),
                        }
                    }
                }

                let (Some(d), Some(crv)) = (d, crv) else {
                    return Err(CryptoError::InvalidKey);
                };
                let crv: i128 = crv.as_integer().ok_or(CryptoError::InvalidKey)?.into();
                if crv == EllipticCurve::Ed25519.to_i64().into() {
                    let secret_key_bytes: &[u8; 32] = d
                        .as_bytes()
                        .ok_or(CryptoError::InvalidKey)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| CryptoError::InvalidKey)?;
                    let key = ed25519_dalek::SigningKey::from_bytes(secret_key_bytes);
                    Ok(SigningKey {
                        id: key_id,
                        inner: RawSigningKey::Ed25519(key),
                    })
                } else {
                    Err(CryptoError::InvalidKey)
                }
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cose_roundtrip_encode_signing() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let cose = signing_key.to_cose().unwrap();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(
            signing_key.to_cose().unwrap(),
            parsed_key.to_cose().unwrap()
        );
    }

    #[test]
    fn test_sign_rountrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let signature = signing_key.sign_raw("Test message".as_bytes());
        let verifying_key = signing_key.to_verifying_key();
        assert!(verifying_key
            .verify_raw(&signature, "Test message".as_bytes())
            .is_ok());
    }
}
