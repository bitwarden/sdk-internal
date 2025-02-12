use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
    #[error(transparent)]
    NotAuthenticated(#[from] bitwarden_core::NotAuthenticatedError),
    #[error(transparent)]
    VaultLocked(#[from] bitwarden_core::VaultLockedError),

    #[error("CSV error: {0}")]
    Csv(#[from] crate::csv::CsvError),
    #[error("Credential Exchange error: {0}")]
    CxfError(#[from] crate::cxf::CxfError),
    #[error("JSON error: {0}")]
    Json(#[from] crate::json::JsonError),
    #[error("Encrypted JSON error: {0}")]
    EncryptedJsonError(#[from] crate::encrypted_json::EncryptedJsonError),

    #[error(transparent)]
    BitwardenCryptoError(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    CipherError(#[from] bitwarden_vault::CipherError),
}
