use bitwarden_core::{Client, FromClient};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::access_rules::AccessRulesClient;

/// Entry point for Privileged Access Management (PAM) operations.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PamClient {
    pub(crate) client: Client,
}

impl PamClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PamClient {
    /// Access rule CRUD operations.
    pub fn access_rules(&self) -> AccessRulesClient {
        AccessRulesClient::from_client(&self.client)
    }
}

/// Extension trait that exposes [`PamClient`] on [`Client`].
pub trait PamClientExt {
    /// Returns a [`PamClient`] backed by this client.
    fn pam(&self) -> PamClient;
}

impl PamClientExt for Client {
    fn pam(&self) -> PamClient {
        PamClient::new(self.clone())
    }
}
