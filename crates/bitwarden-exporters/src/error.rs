use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[expect(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
    #[error(transparent)]
    NotAuthenticated(#[from] bitwarden_core::NotAuthenticatedError),

    #[error("CSV error: {0}")]
    Csv(#[from] crate::csv::CsvError),
    #[error("Credential Exchange error: {0}")]
    Cxf(#[from] crate::cxf::CxfError),
    #[error("JSON error: {0}")]
    Json(#[from] crate::json::JsonError),
    #[error("Encrypted JSON error: {0}")]
    EncryptedJson(#[from] crate::encrypted_json::EncryptedJsonError),

    #[error(transparent)]
    BitwardenCrypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    Cipher(#[from] bitwarden_vault::CipherError),
}
