use std::sync::Arc;

use reqwest_middleware::ClientWithMiddleware;

/// Internal state shared by all clones of a [`crate::GlobalClient`].
///
/// Holds the configured HTTP client and exposes factory methods that build
/// per-call API clients targeting a caller-supplied base URL.
pub struct GlobalInternalClient {
    pub(crate) http_client: ClientWithMiddleware,
}

impl GlobalInternalClient {
    /// Build an API client targeting `base_url`.
    pub fn make_api_client(&self, base_url: String) -> bitwarden_api_api::apis::ApiClient {
        let config = bitwarden_api_api::Configuration {
            base_path: base_url,
            client: self.http_client.clone(),
        };
        bitwarden_api_api::apis::ApiClient::new(&Arc::new(config))
    }

    /// Build an identity client targeting `base_url`.
    pub fn make_identity_client(
        &self,
        base_url: String,
    ) -> bitwarden_api_identity::apis::ApiClient {
        let config = bitwarden_api_identity::Configuration {
            base_path: base_url,
            client: self.http_client.clone(),
        };
        bitwarden_api_identity::apis::ApiClient::new(&Arc::new(config))
    }
}
