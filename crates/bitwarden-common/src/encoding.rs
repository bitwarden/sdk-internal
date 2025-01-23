use base64::{engine::general_purpose::STANDARD, Engine};
use thiserror::Error;

pub trait Encodable<To>: Sized {
    type DecodeError;
    fn encode(&self) -> To;
    fn try_decode(encoded: To) -> Result<Self, Self::DecodeError>;
}

/// A struct representing data that has been encoded to a Base64 string.
/// Guaranteed to only contain valid base64 characters.
pub struct B64Encoded(String);

impl From<B64Encoded> for Vec<u8> {
    fn from(encoded: B64Encoded) -> Vec<u8> {
        STANDARD.decode(&encoded.0).expect("B64Encoded should always contain valid base64")
    }
}

impl TryFrom<Vec<u8>> for B64Encoded {
    type Error = B64DecodeError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, B64DecodeError> {
        let decoded = String::from_utf8(bytes).map_err(|_| B64DecodeError::InvalidUtf8String)?;
        if STANDARD.decode(&decoded).is_err() {
            return Err(B64DecodeError::InvalidBase64);
        }
        Ok(B64Encoded(decoded))
    }
}

#[derive(Debug, Error)]
pub enum B64DecodeError {
    #[error("Invalid base64 string")]
    InvalidBase64,
    #[error("Invalid UTF-8 string")]
    InvalidUtf8String,
}

impl Encodable<B64Encoded> for String {
    type DecodeError = B64DecodeError;
    fn encode(&self) -> B64Encoded {
        B64Encoded(STANDARD.encode(self))
    }

    fn try_decode(encoded: B64Encoded) -> Result<String, B64DecodeError> {
        let decoded = Vec::<u8>::try_decode(encoded)?;
        String::from_utf8(decoded).map_err(|_| B64DecodeError::InvalidUtf8String)
    }
}

impl Encodable<B64Encoded> for Vec<u8> {
    type DecodeError = B64DecodeError;

    fn encode(&self) -> B64Encoded {
        B64Encoded(STANDARD.encode(self))
    }

    fn try_decode(encoded: B64Encoded) -> Result<Self, Self::DecodeError> {
        STANDARD
            .decode(&encoded.0)
            .map_err(|_| B64DecodeError::InvalidBase64)
    }
}
