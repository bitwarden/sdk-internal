#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError<Crypto, Com> {
    CryptoError(Crypto),
    CommunicationError(Com),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError<Crypto, Com> {
    CryptoError(Crypto),
    CommunicationError(Com),
}
