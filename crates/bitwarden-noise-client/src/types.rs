//! Types for the remote client protocol

use serde::{Deserialize, Serialize};

/// Configuration for the remote client connection
#[derive(Debug, Clone)]
pub struct RemoteClientConfig {
    /// WebSocket URL of the proxy server
    pub proxy_url: String,
    /// Username for authentication
    pub username: String,
    /// Pairing code (password:metadata format)
    pub pairing_code: String,
    /// Optional client identifier for this device
    pub client_id: Option<String>,
    /// Whether to use cached authentication if available
    pub use_cached_auth: bool,
}

/// Events emitted by the remote client during connection and operation
#[derive(Debug, Clone)]
pub enum RemoteClientEvent {
    /// Connecting to the proxy server
    Connecting {
        /// The proxy URL being connected to
        proxy_url: String,
    },
    /// Successfully connected to the proxy
    Connected {
        /// The client ID used for this connection
        client_id: String,
    },
    /// Checking for cached authentication
    CacheCheck {
        /// Whether cached auth was found
        has_cached_auth: bool,
        /// Username being authenticated
        username: String,
        /// Client ID if specified
        client_id: Option<String>,
    },
    /// PSK authentication starting
    AuthStart {
        /// Authentication phase
        phase: String,
    },
    /// PSK authentication complete
    AuthComplete {
        /// Authentication phase
        phase: String,
        /// Whether session was cached
        session_cached: bool,
    },
    /// Noise handshake starting
    HandshakeStart,
    /// Noise handshake progress
    HandshakeProgress {
        /// Progress message
        message: String,
    },
    /// Noise handshake complete
    HandshakeComplete,
    /// Client is ready for credential requests
    Ready {
        /// Whether credentials can be requested
        can_request_credentials: bool,
    },
    /// Credential request was sent
    CredentialRequestSent {
        /// Domain requested
        domain: String,
    },
    /// Credential was received
    CredentialReceived {
        /// Domain of the credential
        domain: String,
        /// The credential data
        credential: CredentialData,
    },
    /// An error occurred
    Error {
        /// Error message
        message: String,
        /// Context where error occurred
        context: Option<String>,
    },
    /// Client was disconnected
    Disconnected {
        /// Reason for disconnection
        reason: Option<String>,
    },
}

/// Credential data returned from a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    /// Username for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// TOTP code if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// URI associated with the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Additional notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Internal protocol messages sent over WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum ProtocolMessage {
    /// Authentication message to proxy
    Auth {
        #[serde(rename = "clientId")]
        client_id: Option<String>,
        username: String,
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    /// Authentication response from proxy
    AuthResponse {
        success: bool,
        error: Option<String>,
    },
    /// Indicate using cached authentication
    CachedAuth {
        username: String,
        #[serde(rename = "clientId")]
        client_id: Option<String>,
    },
    /// First-time authentication notification
    FirstTimeAuth {
        username: String,
        #[serde(rename = "clientId")]
        client_id: Option<String>,
    },
    /// Noise handshake message 1 (initiator -> responder)
    #[serde(rename = "noise-message-1")]
    NoiseMessage1 { data: String },
    /// Noise handshake message 2 (responder -> initiator)
    #[serde(rename = "noise-message-2")]
    NoiseMessage2 { data: String },
    /// Noise handshake message 3 (initiator -> responder)
    #[serde(rename = "noise-message-3")]
    NoiseMessage3 { data: String },
    /// Encrypted credential request
    CredentialRequest { encrypted: String },
    /// Encrypted credential response
    CredentialResponse { encrypted: String },
}

/// Internal credential request structure (encrypted in transit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialRequestPayload {
    #[serde(rename = "type")]
    pub request_type: String,
    pub username: String,
    pub domain: String,
    pub timestamp: u64,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

/// Internal credential response structure (encrypted in transit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialResponsePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
