use bitwarden_core::Client;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use crate::platform::repository::create_wasm_repositories;

mod repository;
pub mod token_provider;

/// Active feature flags for the SDK.
#[bitwarden_ffi::wasm_record]
#[derive(Serialize, Deserialize)]
pub struct FeatureFlags {
    /// We intentionally use a loose type here to allow for future flags without breaking changes.
    #[serde(flatten)]
    flags: std::collections::HashMap<String, bool>,
}

#[bitwarden_ffi::wasm_object]
pub struct PlatformClient(Client);

impl PlatformClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[bitwarden_ffi::wasm_export]
impl PlatformClient {
    pub fn state(&self) -> StateClient {
        StateClient::new(self.0.clone())
    }

    /// Load feature flags into the client
    pub async fn load_flags(&self, flags: FeatureFlags) -> Result<(), JsValue> {
        self.0.flags().load(flags.flags).await;
        Ok(())
    }
}

#[bitwarden_ffi::wasm_object]
pub struct StateClient(Client);

impl StateClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

bitwarden_pm::create_client_managed_repositories!(Repositories, create_wasm_repositories);

#[bitwarden_ffi::wasm_export]
impl StateClient {
    pub fn register_client_managed_repositories(&self, repositories: Repositories) {
        repositories.register_all(&self.0.platform().state());
    }
}
