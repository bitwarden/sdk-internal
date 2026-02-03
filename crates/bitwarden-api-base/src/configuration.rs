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
    /// OAuth access token for authentication.
    pub oauth_access_token: Option<String>,

    /// User-Agent header value to be sent with requests.
    /// This is deprecated and kept only for backward compatibility.
    /// Instead we recommend setting the User-Agent via middleware
    /// or reqwest's default headers.
    pub user_agent: Option<String>,
}
