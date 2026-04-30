use std::sync::Arc;

use crate::{
    client::{build_default_headers, new_http_client_builder},
    global::GlobalInternalClient,
};

/// The entry point for unauthenticated SDK operations.
///
/// `GlobalClient` is cheap to clone — every clone shares the same underlying
/// [`GlobalInternalClient`] (wrapped in an [`Arc`]).
///
/// Headers are sourced from the process-wide
/// [`crate::HostPlatformInfo`] singleton, which must be initialized via
/// [`crate::init_host_platform_info`] before constructing a `GlobalClient`.
#[derive(Clone)]
pub struct GlobalClient {
    internal: Arc<GlobalInternalClient>,
}

impl GlobalClient {
    /// Build a `GlobalClient` using the process-wide
    /// [`crate::HostPlatformInfo`].
    ///
    /// # Panics
    /// Panics if [`crate::init_host_platform_info`] has not been called.
    pub fn new() -> Self {
        let info = crate::client::get_host_platform_info();
        let http_client = new_http_client_builder()
            .default_headers(build_default_headers(info))
            .build()
            .expect("Global HTTP Client build should not fail")
            .into();
        Self {
            internal: Arc::new(GlobalInternalClient { http_client }),
        }
    }

    /// Build an API client targeting `base_url`.
    pub fn make_api_client(&self, base_url: String) -> bitwarden_api_api::apis::ApiClient {
        self.internal.make_api_client(base_url)
    }

    /// Build an identity client targeting `base_url`.
    pub fn make_identity_client(
        &self,
        base_url: String,
    ) -> bitwarden_api_identity::apis::ApiClient {
        self.internal.make_identity_client(base_url)
    }
}

impl Default for GlobalClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use reqwest_middleware::ClientBuilder;

    use super::*;

    fn dummy_client() -> GlobalClient {
        GlobalClient {
            internal: Arc::new(GlobalInternalClient {
                http_client: ClientBuilder::new(reqwest::Client::new()).build(),
            }),
        }
    }

    #[test]
    fn clone_shares_internal_state() {
        let original = dummy_client();
        let cloned = original.clone();
        assert!(Arc::ptr_eq(&original.internal, &cloned.internal));
    }
}
