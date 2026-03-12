use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A cookie acquired from the platform
///
/// Represents a single cookie name/value pair as received from the browser or HTTP client.
/// For sharded cookies (AWS ALB pattern), each shard is a separate `AcquiredCookie` with
/// its own name including the `-{N}` suffix (e.g., `AWSELBAuthSessionCookie-0`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AcquiredCookie {
    /// Cookie name
    ///
    /// For sharded cookies, this includes the shard suffix (e.g., `AWSELBAuthSessionCookie-0`)
    /// For unsharded cookies, this is the cookie name without any suffix.
    pub name: String,
    /// Cookie value
    pub value: String,
}

/// Errors that can occur during cookie acquisition
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum AcquireCookieError {
    /// Cookie acquisition was cancelled by the user
    #[error("Cookie acquisition was cancelled")]
    Cancelled,

    /// The server configuration does not support cookie acquisition
    #[error("Server configuration does not support SSO cookie acquisition (Direct bootstrap)")]
    UnsupportedConfiguration,

    /// The acquired cookie name does not match the expected cookie name
    #[error("Cookie name mismatch: expected {expected}, got {actual}")]
    CookieNameMismatch {
        /// Expected cookie name from server configuration
        expected: String,
        /// Actual cookie name returned by platform
        actual: String,
    },

    /// Failed to retrieve server configuration from repository
    #[error("Failed to get server configuration: {0}")]
    RepositoryGetError(String),

    /// Failed to save updated configuration to repository
    #[error("Failed to save server configuration: {0}")]
    RepositorySaveError(String),
}

/// Platform API for acquiring cookies from the platform client
///
/// This trait abstracts the platform-specific logic for acquiring SSO cookies
/// from load balancers. Platform clients (web, mobile, desktop) implement this
/// trait to provide cookie acquisition through browser interactions or native
/// HTTP client capabilities.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
#[async_trait::async_trait]
pub trait ServerCommunicationConfigPlatformApi: Send + Sync {
    /// Acquires cookies for the given hostname
    ///
    /// The platform client should trigger any necessary user interaction
    /// (e.g., browser redirect to IdP) to acquire cookies from the
    /// load balancer.
    ///
    /// # Parameters
    /// - `hostname`: The API hostname (e.g., "api.bitwarden.com" or "localhost")
    /// - `vault_url`: The full vault URL (scheme + host + port, e.g., `"https://vault.bitwarden.com"`
    ///   or `"https://localhost:8000"`)
    ///
    /// The `vault_url` parameter should be used for constructing the redirect URL
    /// instead of deriving it from `hostname`.
    ///
    /// # Returns
    /// Returns `Some(Vec<AcquiredCookie>)` if cookies were successfully acquired,
    /// or `None` if the operation was cancelled or failed.
    async fn acquire_cookies(
        &self,
        hostname: String,
        vault_url: String,
    ) -> Option<Vec<AcquiredCookie>>;
}
