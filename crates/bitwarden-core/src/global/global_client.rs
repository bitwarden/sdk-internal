use std::sync::Arc;

use crate::{
    client::{
        build_default_headers, new_http_client_builder,
        client_settings::ClientSettings,
        internal::ApiConfigurations,
    },
    global::global_internal_client::GlobalInternalClient,
};

/// Client for unauthenticated global operations (e.g. receiving sends).
/// Mirrors the [`crate::Client`]/[`crate::client::internal::InternalClient`] split: `Clone`
/// returns an owned reference to the same underlying state via the inner `Arc`.
#[derive(Clone)]
pub struct GlobalClient {
    #[doc(hidden)]
    pub internal: Arc<GlobalInternalClient>,
}

impl GlobalClient {
    /// Create a new global client. Uses default settings when `None` is provided.
    pub fn new(settings: Option<ClientSettings>) -> Self {
        let settings = settings.unwrap_or_default();
        let headers = build_default_headers(&settings);

        let http_client = new_http_client_builder()
            .default_headers(headers)
            .build()
            .expect("Global HTTP Client build should not fail");

        let identity = bitwarden_api_identity::Configuration {
            base_path: settings.identity_url,
            client: http_client.clone().into(),
        };

        let api = bitwarden_api_api::Configuration {
            base_path: settings.api_url,
            client: http_client.into(),
        };

        let api_configurations = ApiConfigurations::new(identity, api, settings.device_type);

        Self {
            internal: Arc::new(GlobalInternalClient { api_configurations }),
        }
    }
}
