use bitwarden_core::{Client, Flags};
use bitwarden_vault::{Cipher, Folder};
use wasm_bindgen::prelude::*;

mod iter;
mod repository;
pub mod token_provider;

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

    pub fn iter(&self) -> iter::IteratorClient {
        iter::IteratorClient::new(self.0.clone())
    }

    /// Load feature flags into the client
    pub fn load_flags(&self, flags: Flags) -> Result<(), JsValue> {
        self.0.internal.set_flags(&flags);
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
