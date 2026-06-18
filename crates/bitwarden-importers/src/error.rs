use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug)]
pub enum ImportError {
    #[error("The file is not a valid KeePass database (.kdbx)")]
    KdbxInvalidFormat,
    #[error("The KeePass database exceeds the maximum supported size")]
    KdbxFileTooLarge,
    #[error("Incorrect KeePass password or key file")]
    KdbxWrongCredentials,
    #[error("The KeePass database could not be read; it may be corrupted or unsupported")]
    KdbxCorruptOrUnsupported,

    #[error(transparent)]
    NotAuthenticated(#[from] bitwarden_core::NotAuthenticatedError),
    #[error(transparent)]
    Api(#[from] bitwarden_core::ApiError),
    #[error(transparent)]
    BitwardenCrypto(#[from] bitwarden_crypto::CryptoError),
    /// A Keeper importer cryptography operation failed.
    #[error(transparent)]
    KeeperCrypto(#[from] crate::keeper::crypto::KeeperCryptoError),
    /// Encryption from the shared import bridge (`bitwarden_exporters::encrypt_import`).
    #[error(transparent)]
    Export(#[from] bitwarden_exporters::ExportError),
}
