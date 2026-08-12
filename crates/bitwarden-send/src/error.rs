use thiserror::Error;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum SendParseError {
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
    #[error(transparent)]
    DeserializationFailure(#[from] SendItemDeserializationFailure),
}

/// Item does not exist error.
#[derive(Debug, thiserror::Error)]
#[error("Item does not exist")]
pub struct ItemNotFoundError;

/// Unable to deserialize Item-type Send data
#[derive(Debug, thiserror::Error)]
#[error("Send item deserialization failure")]
pub struct SendItemDeserializationFailure;
