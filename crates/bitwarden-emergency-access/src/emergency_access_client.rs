use std::sync::Arc;

use bitwarden_core::{
    Client, FromClient,
    client::{ApiConfigurations, FromClientPart},
};
use bitwarden_vault::CiphersClient;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Client for emergency access operations, performed as the grantee.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct EmergencyAccessClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    pub(crate) ciphers: CiphersClient,
}

impl FromClient for EmergencyAccessClient {
    fn from_client(client: &Client) -> Self {
        Self {
            api_configurations: client.get_part(),
            ciphers: CiphersClient::from_client(client),
        }
    }
}

/// Extension trait that exposes [`EmergencyAccessClient`] on [`Client`].
pub trait EmergencyAccessClientExt {
    /// Returns an [`EmergencyAccessClient`].
    fn emergency_access(&self) -> EmergencyAccessClient;
}

impl EmergencyAccessClientExt for Client {
    fn emergency_access(&self) -> EmergencyAccessClient {
        EmergencyAccessClient::from_client(self)
    }
}
