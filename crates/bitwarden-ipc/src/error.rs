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

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TypedReceiveError<Typing, Crypto, Com> {
    #[error("Typing error: {0}")]
    TypingError(Typing),

    #[error("Crypto error: {0}")]
    CryptoError(Crypto),

    #[error("Communication error: {0}")]
    CommunicationError(Com),
}

impl<Typing, Crypto, Com> From<ReceiveError<Crypto, Com>>
    for TypedReceiveError<Typing, Crypto, Com>
{
    fn from(value: ReceiveError<Crypto, Com>) -> Self {
        match value {
            ReceiveError::CryptoError(crypto) => TypedReceiveError::CryptoError(crypto),
            ReceiveError::CommunicationError(com) => TypedReceiveError::CommunicationError(com),
        }
    }
}
