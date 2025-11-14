use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum HandshakeError {
    #[error("Invalid cipher suite, {0}")]
    InvalidCipherSuite(String),
    #[error("Crypto initialization failed")]
    CryptoInitializationFailed,
    #[error("Invalid handshake start message")]
    InvalidHandshakeStart,
    #[error("Invalid handshake finish message")]
    InvalidHandshakeFinish,

    #[error("Failed to send message")]
    SendFailed,
    #[error("Failed to receive message")]
    ReceiveFailed,
}

#[derive(Debug, Error)]
pub(super) enum PayloadError {
    #[error("Crypto uninitialized")]
    CryptoUninitialized,
    #[error("Failed to parse payload")]
    ParseFailed,
    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Failed to send payload")]
    SendFailed,
}
