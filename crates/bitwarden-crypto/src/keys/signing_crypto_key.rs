use ciborium::{value::Integer, Value};
use coset::{
    iana::{
        self, Algorithm, CoapContentFormat, EllipticCurve, EnumI64, KeyOperation, KeyType,
        OkpKeyParameter,
    },
    CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabel, RegisteredLabelWithPrivate,
};
use rand::rngs::OsRng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;
use zeroize::ZeroizeOnDrop;

use super::{key_id::KeyId, CryptoKey, KEY_ID_SIZE};
use crate::{
    cose::SIGNING_NAMESPACE,
    error::{Result, SignatureError},
    signing::SigningNamespace,
    CryptoError,
};

/// The type of key / signature scheme used for signing and verifying.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl SignatureAlgorithm {
    pub fn default() -> Self {
        SignatureAlgorithm::Ed25519
    }
}

/// A `SigningKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub(crate) enum RawSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
}

/// A `VerifyingKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
pub(crate) enum RawVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// A signing key is a private key used for signing data. An associated `VerifyingKey` can be
/// derived from it.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey {
    pub(crate) id: KeyId,
    pub(crate) inner: RawSigningKey,
}

impl CryptoKey for SigningKey {}

/// A verifying key is a public key used for verifying signatures. It can be published to other
/// users, who can use it to verify that messages were signed by the holder of the corresponding
/// `SigningKey`.
pub struct VerifyingKey {
    id: KeyId,
    pub(crate) inner: RawVerifyingKey,
}

impl SigningKey {
    /// Makes a new signing key for the given signature scheme.
    pub fn make(key_algorithm: SignatureAlgorithm) -> Result<Self> {
        match { key_algorithm } {
            SignatureAlgorithm::Ed25519 => Ok(SigningKey {
                id: KeyId::make(),
                inner: RawSigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng)),
            }),
        }
    }

    pub(crate) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
        }
    }

    /// Serializes the signing key to a COSE-formatted byte array.
    pub fn to_cose(&self) -> Result<Vec<u8>> {
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
    pub fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_key = CoseKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;
        let (key_id, Some(algorithm), key_type) = (cose_key.key_id, cose_key.alg, cose_key.kty)
        else {
            return Err(CryptoError::InvalidKey);
        };
        let key_id: [u8; KEY_ID_SIZE] = key_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let key_id: KeyId = key_id.into();

        match (key_type, algorithm) {
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

    #[allow(unused)]
    fn algorithm(&self) -> SignatureAlgorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }
}

#[allow(unused)]
impl VerifyingKey {
    /// Serializes the verifying key to a COSE-formatted byte array.
    pub fn to_cose(&self) -> Result<Vec<u8>> {
        match &self.inner {
            RawVerifyingKey::Ed25519(key) => coset::CoseKeyBuilder::new_okp_key()
                .key_id((&self.id).into())
                .algorithm(Algorithm::EdDSA)
                .param(
                    OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                )
                // Note: X does not refer to the X coordinate of the public key curve point, but
                // to the verifying key (signature public key), as represented by the curve spec. In
                // the case of Ed25519, this is the compressed Y coordinate. This
                // was ill-defined in earlier drafts of the standard. https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
                .param(
                    OkpKeyParameter::X.to_i64(),
                    Value::Bytes(key.to_bytes().to_vec()),
                )
                .add_key_op(KeyOperation::Verify)
                .build()
                .to_vec()
                .map_err(|_| CryptoError::InvalidKey),
        }
    }

    /// Deserializes a COSE-formatted byte array into a verifying key.
    pub fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_key = coset::CoseKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;

        let (key_id, Some(algorithm), key_type) = (cose_key.key_id, cose_key.alg, cose_key.kty)
        else {
            return Err(CryptoError::InvalidKey);
        };
        let key_id: [u8; KEY_ID_SIZE] = key_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let key_id: KeyId = key_id.into();

        match (key_type, algorithm) {
            (kty, alg)
                if kty == RegisteredLabel::Assigned(KeyType::OKP)
                    && alg == RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA) =>
            {
                let (mut crv, mut x) = (None, None);
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
                        match key {
                            OkpKeyParameter::Crv => {
                                crv.replace(value);
                            }
                            OkpKeyParameter::X => {
                                x.replace(value);
                            }
                            _ => (),
                        }
                    }
                }
                let (Some(x), Some(crv)) = (x, crv) else {
                    return Err(CryptoError::InvalidKey);
                };

                let crv: i128 = crv.as_integer().ok_or(CryptoError::InvalidKey)?.into();
                if crv == iana::EllipticCurve::Ed25519.to_i64().into() {
                    let verifying_key_bytes: &[u8; 32] = x
                        .as_bytes()
                        .ok_or(CryptoError::InvalidKey)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| CryptoError::InvalidKey)?;
                    let verifying_key =
                        ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes)
                            .map_err(|_| CryptoError::InvalidKey)?;
                    Ok(VerifyingKey {
                        id: key_id,
                        inner: RawVerifyingKey::Ed25519(verifying_key),
                    })
                } else {
                    Err(CryptoError::InvalidKey)
                }
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// Returns the signature scheme used by the verifying key.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.inner {
            RawVerifyingKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }
}

/// A signature cryptographically attests to a (namespace, data) pair. The namespace is included in
/// the signature object, the data is not. One data object can be signed multiple times, with
/// different namespaces / by different signers, depending on the application needs.
pub struct Signature(CoseSign1);

impl From<CoseSign1> for Signature {
    fn from(cose_sign1: CoseSign1) -> Self {
        Signature(cose_sign1)
    }
}

#[allow(unused)]
impl Signature {
    pub(crate) fn from_cose(bytes: &[u8]) -> Result<Self, CryptoError> {
        let cose_sign1 =
            CoseSign1::from_slice(bytes).map_err(|_| SignatureError::InvalidSignature)?;
        Ok(Signature(cose_sign1))
    }

    pub(crate) fn to_cose(&self) -> Result<Vec<u8>> {
        self.0
            .clone()
            .to_vec()
            .map_err(|_| SignatureError::InvalidSignature.into())
    }

    pub(crate) fn inner(&self) -> &CoseSign1 {
        &self.0
    }

    pub(crate) fn namespace(&self) -> Result<SigningNamespace> {
        let mut namespace = None;
        for (key, value) in &self.0.protected.header.rest {
            if let Label::Int(key) = key {
                if *key == SIGNING_NAMESPACE {
                    namespace.replace(value);
                }
            }
        }
        let Some(namespace) = namespace else {
            return Err(SignatureError::InvalidNamespace.into());
        };
        let Some(namespace) = namespace.as_integer() else {
            return Err(SignatureError::InvalidNamespace.into());
        };
        let namespace: i128 = namespace.into();
        SigningNamespace::try_from_i64(namespace as i64)
    }

    pub(crate) fn content_type(&self) -> Result<CoapContentFormat, CryptoError> {
        if let RegisteredLabel::Assigned(content_format) = self
            .0
            .protected
            .header
            .content_type
            .clone()
            .ok_or(CryptoError::from(SignatureError::InvalidSignature))?
        {
            Ok(content_format)
        } else {
            Err(SignatureError::InvalidSignature.into())
        }
    }
}

/// A signed object has a cryptographical attestation to a (namespace, data) pair. The namespace and
/// data are included in the signature object.
pub struct SignedObject(pub(crate) CoseSign1);

impl From<CoseSign1> for SignedObject {
    fn from(cose_sign1: CoseSign1) -> Self {
        SignedObject(cose_sign1)
    }
}

impl SignedObject {
    pub fn content_type(&self) -> Result<CoapContentFormat, CryptoError> {
        if let RegisteredLabel::Assigned(content_format) = self
            .0
            .protected
            .header
            .content_type
            .clone()
            .ok_or(CryptoError::from(SignatureError::InvalidSignature))?
        {
            Ok(content_format)
        } else {
            Err(SignatureError::InvalidSignature.into())
        }
    }
}

#[allow(unused)]
impl SignedObject {
    pub(crate) fn from_cose(bytes: &[u8]) -> Result<Self, CryptoError> {
        let cose_sign1 =
            CoseSign1::from_slice(bytes).map_err(|_| SignatureError::InvalidSignature)?;
        Ok(SignedObject(cose_sign1))
    }

    pub(crate) fn to_cose(&self) -> Result<Vec<u8>> {
        self.0
            .clone()
            .to_vec()
            .map_err(|_| SignatureError::InvalidSignature.into())
    }

    pub(crate) fn inner(&self) -> &CoseSign1 {
        &self.0
    }

    pub(crate) fn namespace(&self) -> Result<SigningNamespace> {
        let mut namespace = None;
        for (key, value) in &self.0.protected.header.rest {
            if let Label::Int(key) = key {
                if *key == SIGNING_NAMESPACE {
                    namespace.replace(value);
                }
            }
        }
        let Some(namespace) = namespace else {
            return Err(SignatureError::InvalidNamespace.into());
        };
        let Some(namespace) = namespace.as_integer() else {
            return Err(SignatureError::InvalidNamespace.into());
        };
        SigningNamespace::try_from_i64(
            namespace
                .try_into()
                .map_err(|_| SignatureError::InvalidNamespace)?,
        )
    }

    pub fn payload(&self) -> Result<Vec<u8>> {
        self.0
            .payload
            .as_ref()
            .ok_or(SignatureError::InvalidSignature.into())
            .map(|payload| payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use coset::CoseSign1Builder;

    use super::*;

    #[test]
    fn test_cose_roundtrip_signature() {
        let sig = CoseSign1Builder::new().build();
        let signature = Signature(sig.clone());
        let cose = signature.to_cose().unwrap();
        let parsed_cose = Signature::from_cose(&cose).unwrap();
        assert_eq!(cose, parsed_cose.to_cose().unwrap());
    }

    #[test]
    fn test_cose_roundtrip_signed_object() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let cose = signing_key
            .sign(&"test", &SigningNamespace::ExampleNamespace)
            .unwrap();
        let cose = cose.to_cose().unwrap();
        let parsed_cose = SignedObject::from_cose(&cose).unwrap();
        assert_eq!(cose, parsed_cose.to_cose().unwrap());
    }

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
}
