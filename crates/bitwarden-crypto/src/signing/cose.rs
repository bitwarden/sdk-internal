//! This file contains helper functions to aid in COSE deserialization

use coset::{
    CoseKey, Label, ProtectedHeader, RegisteredLabel,
    iana::{EllipticCurve, EnumI64, OkpKeyParameter},
};

use super::SigningNamespace;
use crate::{
    CryptoError, KEY_ID_SIZE,
    cose::SIGNING_NAMESPACE,
    error::{EncodingError, SignatureError},
    keys::KeyId,
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
            if let Label::Int(key) = key {
                if *key == SIGNING_NAMESPACE {
                    return value.as_integer();
                }
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

/// Helper function to parse the private key `d` from a `CoseKey`.
fn okp_d(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_key
        .params
        .iter()
        .find_map(|(key, value)| match key {
            Label::Int(i) if OkpKeyParameter::from_i64(*i) == Some(OkpKeyParameter::D) => {
                value.as_bytes().map(|v| v.as_slice())
            }
            _ => None,
        })
        .ok_or(EncodingError::MissingValue("OKP private key"))
}

/// Helper function to parse the public key `x` from a `CoseKey`.
fn okp_x(cose_key: &CoseKey) -> Result<&[u8], EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_key
        .params
        .iter()
        .find_map(|(key, value)| match key {
            Label::Int(i) if OkpKeyParameter::from_i64(*i) == Some(OkpKeyParameter::X) => {
                value.as_bytes().map(|v| v.as_slice())
            }
            _ => None,
        })
        .ok_or(EncodingError::MissingValue("OKP public key"))
}

/// Helper function to parse the OKP curve from a `CoseKey`.
fn okp_curve(cose_key: &CoseKey) -> Result<i128, EncodingError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    cose_key
        .params
        .iter()
        .find_map(|(key, value)| match key {
            Label::Int(i) if OkpKeyParameter::from_i64(*i) == Some(OkpKeyParameter::Crv) => {
                value.as_integer().map(i128::from)
            }
            _ => None,
        })
        .ok_or(EncodingError::MissingValue("OKP curve"))
}
