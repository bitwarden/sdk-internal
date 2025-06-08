use bitwarden_core::Client;
use bitwarden_vault::Cipher;
use wasm_bindgen::prelude::wasm_bindgen;

mod repository;

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
}

#[wasm_bindgen]
pub struct StateClient(Client);

impl StateClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

repository::create_wasm_repository!(CipherRepository, Cipher, "Repository<Cipher>");

#[wasm_bindgen]
impl StateClient {
    pub fn register_cipher_repository(&self, store: CipherRepository) {
        let store = store.into_channel_impl();
        self.0.platform().state().register_client_managed(store)
    }
}
