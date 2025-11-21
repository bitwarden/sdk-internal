use thiserror::Error;

#[expect(missing_docs)]
#[derive(Debug, Error)]
pub enum SendParseError {
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
}
