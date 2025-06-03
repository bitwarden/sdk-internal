use thiserror::Error;
use bitwarden_error::bitwarden_error;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[derive(Debug, Error)]
pub enum CollectionsParseError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingFieldError(#[from] bitwarden_core::MissingFieldError),
}
