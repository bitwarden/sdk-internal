use std::sync::Arc;

#[allow(missing_docs)]
pub struct GlobalInternalClient {
    pub(crate) http_client: reqwest_middleware::ClientWithMiddleware,
}

impl GlobalInternalClient {
    /// Construct an API client pointed at the given base URL, using the shared HTTP client.
    pub fn make_api_client(&self, base_url: String) -> bitwarden_api_api::apis::ApiClient {
        let config = Arc::new(bitwarden_api_api::Configuration {
            base_path: base_url,
            client: self.http_client.clone(),
        });
        bitwarden_api_api::apis::ApiClient::new(&config)
    }

    /// Construct an identity client pointed at the given base URL, using the shared HTTP client.
    pub fn make_identity_client(
        &self,
        base_url: String,
    ) -> bitwarden_api_identity::apis::ApiClient {
        let config = Arc::new(bitwarden_api_identity::Configuration {
            base_path: base_url,
            client: self.http_client.clone(),
        });
        bitwarden_api_identity::apis::ApiClient::new(&config)
    }
}
