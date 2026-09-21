use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CollectionDecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Generic error type for collection encryption errors.
///
/// This intentionally mirrors `bitwarden_vault::EncryptError` rather than depending on it, to
/// avoid creating a circular dependency between the `bitwarden-collections` and `bitwarden-vault`
/// crates.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CollectionEncryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum CollectionsParseError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
}
