//! Configuration types for API clients.

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
