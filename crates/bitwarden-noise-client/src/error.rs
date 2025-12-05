//! Error types for the remote client

use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Errors that can occur in the remote client
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RemoteClientError {
    /// Failed to connect to the proxy server
    #[error("Failed to connect to proxy: {0}")]
    ConnectionFailed(String),

    /// WebSocket error occurred
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Authentication with proxy failed
    #[error("Proxy authentication failed: {0}")]
    ProxyAuthFailed(String),

    /// Invalid pairing code format
    #[error("Invalid pairing code: {0}")]
    InvalidPairingCode(String),

    /// Noise protocol error
    #[error("Noise protocol error: {0}")]
    NoiseProtocol(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Timeout waiting for response
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Secure channel not established
    #[error("Secure channel not established")]
    SecureChannelNotEstablished,

    /// Client not initialized
    #[error("Client not initialized - call connect() first")]
    NotInitialized,

    /// Credential request failed
    #[error("Credential request failed: {0}")]
    CredentialRequestFailed(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Session cache error
    #[error("Session cache error: {0}")]
    SessionCache(String),

    /// Keypair storage error
    #[error("Keypair storage error: {0}")]
    KeypairStorage(String),

    /// Channel closed unexpectedly
    #[error("Channel closed")]
    ChannelClosed,
}

impl From<bitwarden_noise::error::NoiseProtocolError> for RemoteClientError {
    fn from(err: bitwarden_noise::error::NoiseProtocolError) -> Self {
        RemoteClientError::NoiseProtocol(err.to_string())
    }
}

impl From<serde_json::Error> for RemoteClientError {
    fn from(err: serde_json::Error) -> Self {
        RemoteClientError::Serialization(err.to_string())
    }
}
