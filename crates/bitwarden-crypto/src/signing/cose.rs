//! This file contains helper functions to aid in COSE deserialization

use coset::{
    CoseKey, Label, ProtectedHeader, RegisteredLabel,
    iana::{AkpKeyParameter, EllipticCurve, EnumI64, OkpKeyParameter},
};
use ml_dsa::B32;

use super::SigningNamespace;
use crate::{
    CryptoError, KEY_ID_SIZE,
    cose::SIGNING_NAMESPACE,
    error::{EncodingError, SignatureError},
    keys::KeyId,
    signing::signing_key::ML_DSA_SEED_SIZE,
};

/// Helper function to extract the namespace from a `ProtectedHeader`. The namespace is a custom
/// header set on the protected headers of the signature object.
pub(super) fn namespace(
    protected_header: &ProtectedHeader,
) -> Result<SigningNamespace, CryptoError> {
    let namespace = protected_header
        .header
        .rest
        .iter()
        .find_map(|(key, value)| {
            if let Label::Int(key) = key
                && *key == SIGNING_NAMESPACE
            {
                return value.as_integer();
            }
            None
        })
        .ok_or(SignatureError::InvalidNamespace)?;

    SigningNamespace::try_from(i128::from(namespace))
}

/// Helper function to extract the content type from a `ProtectedHeader`. The content type is a
/// standardized header set on the protected headers of the signature object. Currently we only
/// support registered values, but PrivateUse values are also allowed in the COSE specification.
pub(super) fn content_type(
    protected_header: &ProtectedHeader,
) -> Result<coset::iana::CoapContentFormat, CryptoError> {
    protected_header
        .header
        .content_type
        .as_ref()
        .and_then(|ct| match ct {
            RegisteredLabel::Assigned(content_format) => Some(*content_format),
            _ => None,
        })
        .ok_or_else(|| SignatureError::InvalidSignature.into())
}

/// Helper function to extract the key ID from a `CoseKey`. The key ID is a standardized header
/// and always set in bitwarden-crypto generated encrypted messages or signatures.
pub(super) fn key_id(cose_key: &CoseKey) -> Result<KeyId, EncodingError> {
    let key_id: [u8; KEY_ID_SIZE] = cose_key
        .key_id
        .as_slice()
        .try_into()
        .map_err(|_| EncodingError::InvalidValue("key id length"))?;
    let key_id: KeyId = key_id.into();
    Ok(key_id)
}

/// Helper function to parse a ed25519 signing key from a `CoseKey`.
pub(super) fn ed25519_signing_key(
    cose_key: &CoseKey,
) -> Result<ed25519_dalek::SigningKey, EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let d = okp_d(cose_key)?;
    let crv = okp_curve(cose_key)?;
    if crv == EllipticCurve::Ed25519.to_i64().into() {
        Ok(ed25519_dalek::SigningKey::from_bytes(
            d.try_into()
                .map_err(|_| EncodingError::InvalidCoseEncoding)?,
        ))
    } else {
        Err(EncodingError::UnsupportedValue("OKP curve"))
    }
}

/// Helper function to parse a ed25519 verifying key from a `CoseKey`.
pub(super) fn ed25519_verifying_key(
    cose_key: &CoseKey,
) -> Result<ed25519_dalek::VerifyingKey, EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let x = okp_x(cose_key)?;
    let crv = okp_curve(cose_key)?;
    if crv == EllipticCurve::Ed25519.to_i64().into() {
        ed25519_dalek::VerifyingKey::from_bytes(
            x.try_into()
                .map_err(|_| EncodingError::InvalidValue("ed25519 OKP verifying key"))?,
        )
        .map_err(|_| EncodingError::InvalidValue("ed25519 OKP verifying key"))
    } else {
        Err(EncodingError::UnsupportedValue("OKP curve"))
    }
}

/// Helper function to look up a parameter in a `CoseKey` by its registered label.
fn cose_param(
    cose_key: &CoseKey,
    param: impl EnumI64 + Copy,
) -> Option<&coset::cbor::value::Value> {
    cose_key.params.iter().find_map(|(key, value)| match key {
        Label::Int(i) if EnumI64::from_i64(*i) == Some(param) => Some(value),
        _ => None,
    })
}

/// Helper function to parse the private key `d` from a `CoseKey`.
fn okp_d(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_param(cose_key, OkpKeyParameter::D)
        .and_then(|v| v.as_bytes().map(Vec::as_slice))
        .ok_or(EncodingError::MissingValue("OKP private key"))
}

/// Helper function to parse the public key `x` from a `CoseKey`.
fn okp_x(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_param(cose_key, OkpKeyParameter::X)
        .and_then(|v| v.as_bytes().map(Vec::as_slice))
        .ok_or(EncodingError::MissingValue("OKP public key"))
}

/// Helper function to parse the OKP curve from a `CoseKey`.
fn okp_curve(cose_key: &CoseKey) -> Result<i128, EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_param(cose_key, OkpKeyParameter::Crv)
        .and_then(|v| v.as_integer().map(i128::from))
        .ok_or(EncodingError::MissingValue("OKP curve"))
}

/// Helper function to parse the private key from an AKP `CoseKey`.
fn akp_priv(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    cose_param(cose_key, AkpKeyParameter::Priv)
        .and_then(|v| v.as_bytes().map(Vec::as_slice))
        .ok_or(EncodingError::MissingValue("AKP private key"))
}

/// Helper function to parse the public key from an AKP `CoseKey`.
fn akp_pub(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    cose_param(cose_key, AkpKeyParameter::Pub)
        .and_then(|v| v.as_bytes().map(Vec::as_slice))
        .ok_or(EncodingError::MissingValue("AKP public key"))
}

/// Helper function to parse an ML-DSA-65 signing key from a `CoseKey`. The `Priv` parameter
/// contains the 32-byte seed, from which the full key pair is deterministically derived.
pub(super) fn mldsa_seed(cose_key: &CoseKey) -> Result<B32, EncodingError> {
    let priv_bytes = akp_priv(cose_key)?;
    let seed: [u8; ML_DSA_SEED_SIZE] = priv_bytes
        .try_into()
        .map_err(|_| EncodingError::InvalidValue("ML-DSA-65 seed length"))?;
    Ok(seed.into())
}

/// Helper function to parse an ML-DSA-44 verifying key from a `CoseKey`.
pub(super) fn mldsa44_verifying_key(
    cose_key: &CoseKey,
) -> Result<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>, EncodingError> {
    let pub_bytes = akp_pub(cose_key)?;
    let vk_encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(pub_bytes)
        .map_err(|_| EncodingError::InvalidValue("ML-DSA-44 verifying key length"))?;
    Ok(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&vk_encoded))
}
