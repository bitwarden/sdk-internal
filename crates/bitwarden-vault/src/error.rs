use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Generic error type for vault encryption errors.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    VaultLocked(#[from] bitwarden_core::VaultLockedError),
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
    #[error(transparent)]
    VaultLocked(#[from] bitwarden_core::VaultLockedError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum VaultParseError {
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingFieldError(#[from] bitwarden_core::MissingFieldError),
}
