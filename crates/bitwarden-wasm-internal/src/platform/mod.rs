use bitwarden_core::Client;
use bitwarden_state::{repository::RepositoryItem, DatabaseConfiguration};
use bitwarden_vault::Cipher;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
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

#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct IndexedDbConfiguration {
    pub db_name: String,
}

#[wasm_bindgen]
impl StateClient {
    pub async fn initialize_state(
        &self,
        configuration: IndexedDbConfiguration,
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
            .initialize_database(configuration.into(), sdk_managed_repositories)
            .await
    }
}

impl From<IndexedDbConfiguration> for DatabaseConfiguration {
    fn from(config: IndexedDbConfiguration) -> Self {
        bitwarden_state::DatabaseConfiguration::IndexedDb {
            db_name: config.db_name,
        }
    }
}
