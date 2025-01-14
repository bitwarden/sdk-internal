use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SendError<Crypto, Com> {
    #[error("Crypto error: {0}")]
    CryptoError(Crypto),

    #[error("Communication error: {0}")]
    CommunicationError(Com),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReceiveError<Crypto, Com> {
    #[error("Crypto error: {0}")]
    CryptoError(Crypto),

    #[error("Communication error: {0}")]
    CommunicationError(Com),
}
