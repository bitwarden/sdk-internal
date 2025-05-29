//! This file contains helper functions to aid in COSE deserialization

use coset::{
    iana::{EllipticCurve, EnumI64, OkpKeyParameter},
    CoseKey, Label, ProtectedHeader, RegisteredLabel,
};

use super::SigningNamespace;
use crate::{
    cose::SIGNING_NAMESPACE, error::SignatureError, keys::KeyId, CryptoError, KEY_ID_SIZE,
};

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

    SigningNamespace::try_from_i64(
        i128::from(namespace)
            .try_into()
            .map_err(|_| SignatureError::InvalidNamespace)?,
    )
}

pub(super) fn content_type(
    protected_header: &ProtectedHeader,
) -> Result<coset::iana::CoapContentFormat, CryptoError> {
    if let RegisteredLabel::Assigned(content_format) = protected_header
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

pub(super) fn key_id(cose_key: &CoseKey) -> Result<KeyId, CryptoError> {
    let key_id: [u8; KEY_ID_SIZE] = cose_key
        .key_id
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let key_id: KeyId = key_id.into();
    Ok(key_id)
}

pub(super) fn ed25519_signing_key(
    cose_key: &CoseKey,
) -> Result<ed25519_dalek::SigningKey, CryptoError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let d = okp_d(cose_key)?;
    let crv = okp_curve(cose_key)?;
    if crv == EllipticCurve::Ed25519.to_i64().into() {
        Ok(ed25519_dalek::SigningKey::from_bytes(
            d.try_into().map_err(|_| CryptoError::InvalidKey)?,
        ))
    } else {
        Err(CryptoError::InvalidKey)
    }
}

pub(super) fn ed25519_verifying_key(
    cose_key: &CoseKey,
) -> Result<ed25519_dalek::VerifyingKey, CryptoError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let x = okp_x(cose_key)?;
    let crv = okp_curve(cose_key)?;
    if crv == EllipticCurve::Ed25519.to_i64().into() {
        Ok(ed25519_dalek::VerifyingKey::from_bytes(
            x.try_into().map_err(|_| CryptoError::InvalidKey)?,
        )
        .map_err(|_| CryptoError::InvalidKey)?)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

fn okp_d(cose_key: &CoseKey) -> Result<&[u8], CryptoError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let mut d = None;
    for (key, value) in &cose_key.params {
        if let Label::Int(i) = key {
            let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
            if key == OkpKeyParameter::D {
                d.replace(value);
            }
        }
    }
    let d = d.ok_or(CryptoError::InvalidKey)?;
    Ok(d.as_bytes().ok_or(CryptoError::InvalidKey)?.as_slice())
}

fn okp_x(cose_key: &CoseKey) -> Result<&[u8], CryptoError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let mut x = None;
    for (key, value) in &cose_key.params {
        if let Label::Int(i) = key {
            let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
            if key == OkpKeyParameter::X {
                x.replace(value);
            }
        }
    }
    let x = x.ok_or(CryptoError::InvalidKey)?;
    Ok(x.as_bytes().ok_or(CryptoError::InvalidKey)?.as_slice())
}

fn okp_curve(cose_key: &CoseKey) -> Result<i128, CryptoError> {
    // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
    let mut crv = None;
    for (key, value) in &cose_key.params {
        if let Label::Int(i) = key {
            let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
            if key == OkpKeyParameter::Crv {
                crv.replace(value);
            }
        }
    }

    let crv = crv.ok_or(CryptoError::InvalidKey)?;
    Ok(crv.as_integer().ok_or(CryptoError::InvalidKey)?.into())
}
