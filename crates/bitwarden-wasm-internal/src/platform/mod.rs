use bitwarden_core::Client;
use bitwarden_vault::{Cipher, Folder};
use tsify::{serde_wasm_bindgen, Tsify};
use wasm_bindgen::prelude::*;

mod repository;
pub mod token_provider;

#[derive(serde::Serialize, serde::Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct FlagsInput {
    #[serde(rename = "enableCipherKeyEncryption")]
    pub enable_cipher_key_encryption: Option<bool>,
}

impl From<FlagsInput> for std::collections::HashMap<String, bool> {
    fn from(flags: FlagsInput) -> Self {
        let js_value = serde_wasm_bindgen::to_value(&flags)
            .expect("FlagsInput should always serialize successfully");

        serde_wasm_bindgen::from_value(js_value)
            .unwrap_or_else(|_| std::collections::HashMap::new())
    }
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
    pub fn load_flags(&self, flags: FlagsInput) -> Result<(), JsValue> {
        self.0.internal.load_flags(flags.into());
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
