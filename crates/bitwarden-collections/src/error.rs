use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[expect(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CollectionDecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[expect(missing_docs)]
#[derive(Debug, Error)]
pub enum CollectionsParseError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
}
