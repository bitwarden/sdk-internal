use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{CipherError, cipher::blob::BlobEncryptionError};

/// Generic error type for vault encryption errors.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    BlobEncryption(#[from] BlobEncryptionError),
    #[error("Client User Id has not been set")]
    MissingUserId,
}

/// Generic error type for decryption errors
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// A cipher list decrypt failed.
///
/// `decrypt_list_with_failures` and `decrypt_list_full_with_failures` report ciphers that fail to
/// decrypt in their result, so they only return [`DecryptListError::InvalidInput`].
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptListError {
    /// A cipher failed to decrypt.
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    /// An item of the input list is not valid.
    #[error(transparent)]
    InvalidInput(#[from] bitwarden_ffi::LargeVecError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum VaultParseError {
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

impl From<VaultParseError> for CipherError {
    fn from(e: VaultParseError) -> Self {
        match e {
            VaultParseError::Crypto(e) => Self::Crypto(e),
            VaultParseError::MissingField(e) => Self::MissingField(e),
            VaultParseError::Chrono(e) => Self::Chrono(e),
            VaultParseError::SerdeJson(e) => Self::SerdeJson(e),
        }
    }
}
