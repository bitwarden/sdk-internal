use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::access_rules::AccessRulesClient;

/// Entry point for Privileged Access Management (PAM) operations.
#[derive(Clone, FromClient)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PamClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PamClient {
    /// Access rule CRUD operations.
    pub fn access_rules(&self) -> AccessRulesClient {
        AccessRulesClient {
            api_configurations: self.api_configurations.clone(),
        }
    }
}

/// Extension trait that exposes [`PamClient`] on [`Client`].
pub trait PamClientExt {
    /// Returns a [`PamClient`] backed by this client.
    fn pam(&self) -> PamClient;
}

impl PamClientExt for Client {
    fn pam(&self) -> PamClient {
        PamClient::from_client(self)
    }
}
