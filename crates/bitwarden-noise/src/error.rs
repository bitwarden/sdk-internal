use bitwarden_error::bitwarden_error;
use thiserror::Error;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum NoiseProtocolError {
    #[error("Failed to parse pattern")]
    NoisePatternParse,
    #[error("Failed to generate keypair")]
    KeypairGeneration,
    #[error("Static secret key must be 32 bytes")]
    StaticSecretKeyLength,
    #[error("PSK must be 32 bytes")]
    BadPskLength,
    #[error("Failed to build initiator")]
    Initiator,
    #[error("Failed to build responder")]
    Responder,
    #[error("Handshake already complete")]
    HandshakeAlreadyComplete,
    #[error("Handshake not initialized")]
    HandshakeNotInitialized,
    #[error("Write error during handshake")]
    HandshakeWriteError,
    #[error("Read error during handshake")]
    HandshakeReadError,
    #[error("Failed to split handshake")]
    HandshakeSplit,
    #[error("Handshake not complete")]
    HandshakeNotComplete,
    #[error("Transport not initialized")]
    TransportNotInitialized,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Remote static key not available after split")]
    RemoteStaticKeyNotAvailable,
    #[error("Handshake already complete, use encrypt() instead")]
    UseEncryptInstead,
    #[error("Handshake already complete, use decrypt() instead")]
    UseDecryptInstead,
    #[error("Invalid protocol handle")]
    InvalidHandle,
    #[error("Protocol store lock poisoned")]
    LockPoisoned,
}
