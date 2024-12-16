use bitwarden_error::prelude::*;
use thiserror::Error;

#[bitwarden_error(flat)]
#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to generate key: {0}")]
    KeyGenerationError(ssh_key::Error),
    #[error("Failed to convert key: {0}")]
    KeyConversionError(ssh_key::Error),
}

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
