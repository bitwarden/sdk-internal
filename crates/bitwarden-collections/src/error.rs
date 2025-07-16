use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CollectionDecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum CollectionsParseError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingFieldError(#[from] bitwarden_core::MissingFieldError),
}
