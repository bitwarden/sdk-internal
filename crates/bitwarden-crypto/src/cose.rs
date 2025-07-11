//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a a clear benefit, such as a clear cryptographic benefit, which MUST
//! be documented publicly.

use coset::{
    iana::{self, CoapContentFormat},
    ContentType, Label,
};

use crate::{
    content_format::{Bytes, ConstContentFormat, CoseContentFormat},
    error::{EncStringParseError, EncodingError},
    ContentFormat, CryptoError,
};

/// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
/// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
/// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
pub(crate) const XCHACHA20_TEXT_PAD_BLOCK_SIZE: usize = 32;

// Note: These are in the "unregistered" tree: https://datatracker.ietf.org/doc/html/rfc6838#section-3.4
// These are only used within Bitwarden, and not meant for exchange with other systems.
const CONTENT_TYPE_PADDED_UTF8: &str = "application/x.bitwarden.utf8-padded";
const CONTENT_TYPE_BITWARDEN_LEGACY_KEY: &str = "application/x.bitwarden.legacy-key";
const CONTENT_TYPE_SPKI_PUBLIC_KEY: &str = "application/x.bitwarden.spki-public-key";

// Labels
//
/// The label used for the namespace ensuring strong domain separation when using signatures.
pub(crate) const SIGNING_NAMESPACE: i64 = -80000;

pub(crate) const SYMMETRIC_KEY: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);

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
            ContentFormat::BitwardenLegacyKey => {
                header_builder.content_type(CONTENT_TYPE_BITWARDEN_LEGACY_KEY.to_string())
            }
            ContentFormat::OctetStream => {
                header_builder.content_format(CoapContentFormat::OctetStream)
            }
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
