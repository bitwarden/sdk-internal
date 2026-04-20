use std::sync::Arc;

use crate::{
    client::{build_default_headers, client_settings::ClientSettings, new_http_client_builder},
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
            .expect("Global HTTP Client build should not fail")
            .into();

        Self {
            internal: Arc::new(GlobalInternalClient { http_client }),
        }
    }
}
