use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SendError<Crypto, Com> {
    #[error("Crypto error: {0}")]
    Crypto(Crypto),

    #[error("Communication error: {0}")]
    Communication(Com),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReceiveError<Crypto, Com> {
    #[error("The receive operation timed out")]
    Timeout,

    #[error("Crypto error: {0}")]
    Crypto(Crypto),

    #[error("Communication error: {0}")]
    Communication(Com),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TypedReceiveError<Typing, Crypto, Com> {
    #[error("Typing error: {0}")]
    Typing(Typing),

    #[error("The receive operation timed out")]
    Timeout,

    #[error("Crypto error: {0}")]
    Crypto(Crypto),

    #[error("Communication error: {0}")]
    Communication(Com),
}

impl<Typing, Crypto, Com> From<ReceiveError<Crypto, Com>>
    for TypedReceiveError<Typing, Crypto, Com>
{
    fn from(value: ReceiveError<Crypto, Com>) -> Self {
        match value {
            ReceiveError::Timeout => TypedReceiveError::Timeout,
            ReceiveError::Crypto(crypto) => TypedReceiveError::Crypto(crypto),
            ReceiveError::Communication(com) => TypedReceiveError::Communication(com),
        }
    }
}
