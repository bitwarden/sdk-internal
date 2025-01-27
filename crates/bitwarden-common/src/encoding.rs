use std::convert::Infallible;

use thiserror::Error;
use base64::{engine::general_purpose::STANDARD, Engine};

pub trait Encodable<To>: Sized {
    // type DecodeError;
    fn encode(&self) -> To;
    // fn try_decode(encoded: To) -> Result<Self, Self::DecodeError>;
}

pub trait Decodable<To: Encodable<Self>>: Sized {
    type DecodeError;
    fn try_decode(self) -> Result<To, Self::DecodeError>;
}

/// A struct representing data that has been encoded to a Base64 string.
/// Guaranteed to only contain valid base64 characters.
pub struct B64Encoded (String);

impl From<B64Encoded> for Vec<u8> {
    fn from(encoded: B64Encoded) -> Vec<u8> {
        STANDARD.decode(&encoded.0).unwrap()
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
    fn encode(&self) -> B64Encoded {
        B64Encoded(STANDARD.encode(self))
    }
}

impl Decodable<String> for B64Encoded {
    type DecodeError = B64DecodeError;
    fn try_decode(self) -> Result<String, B64DecodeError> {
        let decoded: Vec::<u8> = self.try_decode()?;
        Ok(String::from_utf8(decoded).map_err(|_| B64DecodeError::InvalidUtf8String)?)
    }
}

impl Encodable<B64Encoded> for Vec<u8> {
    fn encode(&self) -> B64Encoded {
        B64Encoded(STANDARD.encode(&self))
    }
}

impl Decodable<Vec<u8>> for B64Encoded {
    type DecodeError = B64DecodeError;

    fn try_decode(self) -> Result<Vec<u8>, Self::DecodeError> {
        Ok(STANDARD.decode(&self.0).map_err(|_| B64DecodeError::InvalidBase64)?)
    }
}

impl Encodable<Vec<u8>> for Vec<u8> {
    fn encode(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Decodable<Vec<u8>> for Vec<u8> {
    type DecodeError = Infallible;
    fn try_decode(self) -> Result<Vec<u8>, Self::DecodeError> {
        Ok(self)
    }
}

impl Encodable<Vec<u8>> for &[u8] {
    fn encode(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Encodable<Vec<u8>> for String {

    fn encode(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Decodable<String> for Vec<u8> {
    type DecodeError = std::string::FromUtf8Error;
    fn try_decode(self) -> Result<String, Self::DecodeError> {
        Ok(String::from_utf8(self)?)
    }
}

impl Encodable<Vec<u8>> for &str {
    fn encode(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
