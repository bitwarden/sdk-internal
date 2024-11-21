use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to generate key: {0}")]
    KeyGenerationError(String),
    #[error("Failed to convert key: {0}")]
    KeyConversionError(String),
}
