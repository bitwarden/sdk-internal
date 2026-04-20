use bitwarden_core::Client;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use crate::platform::repository::{create_wasm_repositories, create_wasm_values};

mod repository;
pub mod token_provider;

/// Active feature flags for the SDK.
#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct FeatureFlags {
    /// We intentionally use a loose type here to allow for future flags without breaking changes.
    #[serde(flatten)]
    flags: std::collections::HashMap<String, bool>,
}

#[wasm_bindgen]
pub struct PlatformClient(Client);

impl PlatformClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl PlatformClient {
    pub fn state(&self) -> StateClient {
        StateClient::new(self.0.clone())
    }

    /// Load feature flags into the client
    pub async fn load_flags(&self, flags: FeatureFlags) -> Result<(), JsValue> {
        self.0.internal.load_flags(flags.flags).await;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct StateClient(Client);

impl StateClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

bitwarden_pm::create_client_managed_repositories!(Repositories, create_wasm_repositories);
bitwarden_pm::create_client_managed_values!(Values, create_wasm_values);

#[wasm_bindgen]
impl StateClient {
    #[allow(deprecated)]
    #[deprecated(note = "Use `register_client_managed_repositories` instead")]
    pub fn register_cipher_repository(&self, cipher_repository: CipherRepository) {
        let cipher = cipher_repository.into_channel_impl();
        self.0.platform().state().register_client_managed(cipher);
    }

    #[allow(deprecated)]
    #[deprecated(note = "Use `register_client_managed_repositories` instead")]
    pub fn register_folder_repository(&self, store: FolderRepository) {
        let store = store.into_channel_impl();
        self.0.platform().state().register_client_managed(store)
    }

    pub fn register_client_managed_repositories(&self, repositories: Repositories) {
        repositories.register_all(&self.0.platform().state());
    }

    pub fn register_client_managed_values(&self, values: Values) {
        values.register_all(&self.0.platform().state());
    }
}
