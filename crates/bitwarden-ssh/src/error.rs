use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[expect(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to generate key: {0}")]
    KeyGeneration(ssh_key::Error),
    #[error("Failed to convert key")]
    KeyConversion,
}

#[expect(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug, PartialEq)]
pub enum SshKeyImportError {
    #[error("Failed to parse key")]
    Parsing,
    #[error("Password required")]
    PasswordRequired,
    #[error("Wrong password")]
    WrongPassword,
    #[error("Unsupported key type")]
    UnsupportedKeyType,
}

#[expect(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Error, Debug, PartialEq)]
pub enum SshKeyExportError {
    #[error("Failed to convert key")]
    KeyConversion,
}
