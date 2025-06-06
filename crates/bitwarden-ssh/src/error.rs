use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to generate key: {0}")]
    KeyGenerationError(ssh_key::Error),
    #[error("Failed to convert key")]
    KeyConversionError,
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug, PartialEq)]
pub enum SshKeyImportError {
    #[error("Failed to parse key")]
    ParsingError,
    #[error("Password required")]
    PasswordRequired,
    #[error("Wrong password")]
    WrongPassword,
    #[error("Unsupported key type")]
    UnsupportedKeyType,
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug, PartialEq)]
pub enum SshKeyExportError {
    #[error("Failed to convert key")]
    KeyConversionError,
}
