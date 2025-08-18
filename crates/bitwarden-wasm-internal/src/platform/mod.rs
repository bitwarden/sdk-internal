use bitwarden_core::Client;
use bitwarden_vault::{Cipher, Folder};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

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
    pub fn load_flags(&self, flags: FeatureFlags) -> Result<(), JsValue> {
        self.0.internal.load_flags(flags.flags);
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

repository::create_wasm_repository!(CipherRepository, Cipher, "Repository<Cipher>");
repository::create_wasm_repository!(FolderRepository, Folder, "Repository<Folder>");

#[wasm_bindgen]
impl StateClient {
    pub fn register_cipher_repository(&self, store: CipherRepository) {
        let store = store.into_channel_impl();
        self.0.platform().state().register_client_managed(store)
    }

    pub fn register_folder_repository(&self, store: FolderRepository) {
        let store = store.into_channel_impl();
        self.0.platform().state().register_client_managed(store)
    }
}
