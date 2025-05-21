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
    pub fn repository(&self) -> RepositoryClient {
        RepositoryClient::new(self.0.clone())
    }
}

#[wasm_bindgen]
pub struct RepositoryClient(Client);

impl RepositoryClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

repository::create_wasm_repository!(CipherRepository, Cipher, "Repository<Cipher>");

#[wasm_bindgen]
impl RepositoryClient {
    pub fn register_cipher_repository(&self, store: CipherRepository) {
        let store = store.into_channel_impl();
        self.0.internal.register_repository(store);
    }
}
