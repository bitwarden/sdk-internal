//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a a clear benefit, such as a clear cryptographic benefit, which MUST
//! be documented publicly.

use std::fmt::Debug;

pub(crate) mod symmetric;

use coset::{
    ContentType, Header, Label,
    iana::{self, CoapContentFormat, KeyOperation},
};
use hybrid_array::Array;
use thiserror::Error;
use typenum::U32;

use crate::{
    ContentFormat, CryptoError, SymmetricCryptoKey, XChaCha20Poly1305Key,
    content_format::{Bytes, ConstContentFormat, CoseContentFormat},
    error::{EncStringParseError, EncodingError},
};

// Custom COSE algorithm values
// NOTE: Any algorithm value below -65536 is reserved for private use in the IANA allocations and
// can be used freely.
/// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
/// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
/// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
pub(crate) const ALG_ARGON2ID13: i64 = -71000;

// Custom labels for COSE headers
// NOTE: Any label below -65536 is reserved for private use in the IANA allocations and can be used
// freely.
pub(crate) const ARGON2_SALT: i64 = -71001;
pub(crate) const ARGON2_ITERATIONS: i64 = -71002;
pub(crate) const ARGON2_MEMORY: i64 = -71003;
pub(crate) const ARGON2_PARALLELISM: i64 = -71004;
/// Indicates for any object containing a key (wrapped key, password protected key envelope) which
/// key ID that contained key has
pub(crate) const CONTAINED_KEY_ID: i64 = -71005;

// Note: These are in the "unregistered" tree: https://datatracker.ietf.org/doc/html/rfc6838#section-3.4
// These are only used within Bitwarden, and not meant for exchange with other systems.
const CONTENT_TYPE_PADDED_UTF8: &str = "application/x.bitwarden.utf8-padded";
pub(crate) const CONTENT_TYPE_PADDED_CBOR: &str = "application/x.bitwarden.cbor-padded";
const CONTENT_TYPE_BITWARDEN_LEGACY_KEY: &str = "application/x.bitwarden.legacy-key";
const CONTENT_TYPE_SPKI_PUBLIC_KEY: &str = "application/x.bitwarden.spki-public-key";

/// The label used for the namespace ensuring strong domain separation when using signatures.
pub(crate) const SIGNING_NAMESPACE: i64 = -80000;

// Domain separation / Namespaces
//
// Cryptographic objects are strongly domain separated so that items can only be decrypted
// in the correct context, making cryptographic analysis significantly easier and preventing
// misuse of cryptographic objects. For this, there is a partitioning at two layers. First,
// the object types are partitioned into e.g. EncString, DataEnvelope, Signature, KeyEnvelope, and
// so on. Second, within each of these types, each of these spans their own namespace for usages.
// For instance, a DataEnvelope may describe that the contained item is only valid as a vault item,
// or as account settings.

/// MUST be placed in the protected header of cose objects
pub(crate) const SAFE_OBJECT_NAMESPACE: i64 = -80002;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafeObjectNamespace {
    PasswordProtectedKeyEnvelope = 1,
    DataEnvelope = 2,
    SymmetricKeyEnvelope = 3,
    //Reserved:
    //PrivateKeyEnvelope = 4,
    //SigningKeyEnvelope = 5,
    SecretProtectedKeyEnvelope = 6,
}

impl TryFrom<i128> for SafeObjectNamespace {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SafeObjectNamespace::PasswordProtectedKeyEnvelope),
            2 => Ok(SafeObjectNamespace::DataEnvelope),
            3 => Ok(SafeObjectNamespace::SymmetricKeyEnvelope),
            6 => Ok(SafeObjectNamespace::SecretProtectedKeyEnvelope),
            _ => Err(()),
        }
    }
}

impl From<SafeObjectNamespace> for i128 {
    fn from(namespace: SafeObjectNamespace) -> Self {
        namespace as i128
    }
}

pub(crate) trait ContentNamespace: TryFrom<i128> + Into<i128> + PartialEq + Debug {}

/// Each type of object has it's own namespace for strong domain separation to eliminate
/// attacks which attempt to confuse object types. For signatures, this refers to signature
/// namespaces, for data envelopes to data envelope namespaces and so on.
pub(crate) const SAFE_CONTENT_NAMESPACE: i64 = -80001;

const SYMMETRIC_KEY: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);

impl TryFrom<&coset::CoseKey> for SymmetricCryptoKey {
    type Error = CryptoError;

    #[bitwarden_logging::instrument(err)]
    fn try_from(cose_key: &coset::CoseKey) -> Result<Self, Self::Error> {
        let key_bytes = cose_key
            .params
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (&SYMMETRIC_KEY, ciborium::Value::Bytes(bytes)) => Some(bytes),
                _ => None,
            })
            .ok_or(CryptoError::InvalidKey)?;
        let alg = cose_key.alg.as_ref().ok_or(CryptoError::InvalidKey)?;
        let key_opts = cose_key
            .key_ops
            .iter()
            .map(|op| match op {
                coset::RegisteredLabel::Assigned(iana::KeyOperation::Encrypt) => {
                    Ok(KeyOperation::Encrypt)
                }
                coset::RegisteredLabel::Assigned(iana::KeyOperation::Decrypt) => {
                    Ok(KeyOperation::Decrypt)
                }
                coset::RegisteredLabel::Assigned(iana::KeyOperation::WrapKey) => {
                    Ok(KeyOperation::WrapKey)
                }
                coset::RegisteredLabel::Assigned(iana::KeyOperation::UnwrapKey) => {
                    Ok(KeyOperation::UnwrapKey)
                }
                _ => Err(CryptoError::InvalidKey),
            })
            .collect::<Result<Vec<KeyOperation>, CryptoError>>()?;

        match alg {
            coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) => {
                let enc_key = Box::pin(
                    Array::<u8, U32>::try_from(key_bytes).map_err(|_| CryptoError::InvalidKey)?,
                );
                let key_id = cose_key
                    .key_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey)?;
                Ok(SymmetricCryptoKey::XChaCha20Poly1305Key(
                    XChaCha20Poly1305Key {
                        enc_key,
                        key_id,
                        supported_operations: key_opts,
                    },
                ))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

impl From<ContentFormat> for coset::HeaderBuilder {
    fn from(format: ContentFormat) -> Self {
        let header_builder = coset::HeaderBuilder::new();

        match format {
            ContentFormat::Utf8 => {
                header_builder.content_type(CONTENT_TYPE_PADDED_UTF8.to_string())
            }
            ContentFormat::Pkcs8PrivateKey => {
                header_builder.content_format(CoapContentFormat::Pkcs8)
            }
            ContentFormat::SPKIPublicKeyDer => {
                header_builder.content_type(CONTENT_TYPE_SPKI_PUBLIC_KEY.to_string())
            }
            ContentFormat::CoseSign1 => header_builder.content_format(CoapContentFormat::CoseSign1),
            ContentFormat::CoseKey => header_builder.content_format(CoapContentFormat::CoseKey),
            ContentFormat::CoseEncrypt0 => {
                header_builder.content_format(CoapContentFormat::CoseEncrypt0)
            }
            ContentFormat::BitwardenLegacyKey => {
                header_builder.content_type(CONTENT_TYPE_BITWARDEN_LEGACY_KEY.to_string())
            }
            ContentFormat::OctetStream => {
                header_builder.content_format(CoapContentFormat::OctetStream)
            }
            ContentFormat::Cbor => header_builder.content_format(CoapContentFormat::Cbor),
        }
    }
}

impl TryFrom<&coset::Header> for ContentFormat {
    type Error = CryptoError;

    fn try_from(header: &coset::Header) -> Result<Self, Self::Error> {
        match header.content_type.as_ref() {
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_PADDED_UTF8 => {
                Ok(ContentFormat::Utf8)
            }
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_BITWARDEN_LEGACY_KEY => {
                Ok(ContentFormat::BitwardenLegacyKey)
            }
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_SPKI_PUBLIC_KEY => {
                Ok(ContentFormat::SPKIPublicKeyDer)
            }
            Some(ContentType::Assigned(CoapContentFormat::Pkcs8)) => {
                Ok(ContentFormat::Pkcs8PrivateKey)
            }
            Some(ContentType::Assigned(CoapContentFormat::CoseKey)) => Ok(ContentFormat::CoseKey),
            Some(ContentType::Assigned(CoapContentFormat::OctetStream)) => {
                Ok(ContentFormat::OctetStream)
            }
            Some(ContentType::Assigned(CoapContentFormat::Cbor)) => Ok(ContentFormat::Cbor),
            _ => Err(CryptoError::EncString(
                EncStringParseError::CoseMissingContentType,
            )),
        }
    }
}

/// Trait for structs that are serializable to COSE objects.
pub trait CoseSerializable<T: CoseContentFormat + ConstContentFormat> {
    /// Serializes the struct to COSE serialization
    fn to_cose(&self) -> Bytes<T>;
    /// Deserializes a serialized COSE object to a struct
    fn from_cose(bytes: &Bytes<T>) -> Result<Self, EncodingError>
    where
        Self: Sized;
}

pub(crate) fn extract_integer(
    header: &Header,
    target_label: i64,
    value_name: &str,
) -> Result<i128, CoseExtractError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Int(label_value), ciborium::Value::Integer(int_value))
                if *label_value == target_label =>
            {
                Some(*int_value)
            }
            _ => None,
        })
        .map(Into::into)
        .ok_or_else(|| CoseExtractError::MissingValue(value_name.to_string()))
}

pub(crate) fn extract_bytes(
    header: &Header,
    target_label: i64,
    value_name: &str,
) -> Result<Vec<u8>, CoseExtractError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Int(label_value), ciborium::Value::Bytes(byte_value))
                if *label_value == target_label =>
            {
                Some(byte_value.clone())
            }
            _ => None,
        })
        .ok_or(CoseExtractError::MissingValue(value_name.to_string()))
}

#[derive(Debug, Error)]
pub(crate) enum CoseExtractError {
    #[error("Missing value {0}")]
    MissingValue(String),
}

/// Helper function to convert a COSE KeyOperation to a debug string
pub(crate) fn debug_key_operation(key_operation: KeyOperation) -> &'static str {
    match key_operation {
        KeyOperation::Sign => "Sign",
        KeyOperation::Verify => "Verify",
        KeyOperation::Encrypt => "Encrypt",
        KeyOperation::Decrypt => "Decrypt",
        KeyOperation::WrapKey => "WrapKey",
        KeyOperation::UnwrapKey => "UnwrapKey",
        KeyOperation::DeriveKey => "DeriveKey",
        KeyOperation::DeriveBits => "DeriveBits",
        _ => "Unknown",
    }
}
