//! Configuration types for API clients.

use crate::client::new_http_client;

/// Configuration for an API client.
///
/// This struct provides all the configuration options needed for making
/// authenticated HTTP requests to Bitwarden APIs.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// Base URL path for the API (e.g., "<https://api.bitwarden.com>" or "<https://identity.bitwarden.com>").
    pub base_path: String,
    /// HTTP client with middleware support.
    pub client: reqwest_middleware::ClientWithMiddleware,
}

impl Configuration {
    /// Build a `Configuration` pointing at `base_path` with a default HTTP client
    /// configured by [`new_http_client`].
    pub fn new(base_path: impl Into<String>) -> Self {
        Self {
            base_path: base_path.into(),
            client: new_http_client().into(),
        }
    }
}
