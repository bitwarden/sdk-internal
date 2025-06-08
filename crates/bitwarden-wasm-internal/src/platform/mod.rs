use bitwarden_core::Client;
use bitwarden_state::repository::RepositoryItem;
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
    pub async fn initialize_state(
        &self,
        cipher_repository: CipherRepository,
    ) -> Result<(), bitwarden_state::registry::StateRegistryError> {
        let cipher = cipher_repository.into_channel_impl();
        self.0.platform().state().register_client_managed(cipher);

        let sdk_managed_repositories = vec![
            // This should list all the SDK-managed repositories
            <Cipher as RepositoryItem>::data(),
        ];

        self.0
            .platform()
            .state()
            .initialize_database(sdk_managed_repositories)
            .await
    }
}
