#![allow(deprecated)]

use std::sync::Arc;

use bitwarden_core::{Client, platform::FingerprintRequest};
use bitwarden_fido::ClientFido2Ext;
use bitwarden_state::DatabaseConfiguration;
use repository::{UniffiRepositoryBridge, create_uniffi_repositories};

use crate::error::Result;

mod fido2;
mod repository;
mod server_communication_config;

#[derive(uniffi::Object)]
pub struct PlatformClient(pub(crate) bitwarden_core::Client);

#[uniffi::export]
impl PlatformClient {
    /// Fingerprint (public key)
    pub fn fingerprint(&self, req: FingerprintRequest) -> Result<String> {
        Ok(self.0.platform().fingerprint(&req)?)
    }

    /// Fingerprint using logged in user's public key
    pub fn user_fingerprint(&self, fingerprint_material: String) -> Result<String> {
        Ok(self.0.platform().user_fingerprint(fingerprint_material)?)
    }

    /// Load feature flags into the client
    pub fn load_flags(&self, flags: std::collections::HashMap<String, bool>) -> Result<()> {
        self.0.internal.load_flags(flags);
        Ok(())
    }

    /// FIDO2 operations
    pub fn fido2(&self) -> fido2::ClientFido2 {
        fido2::ClientFido2(self.0.fido2())
    }

    pub fn state(&self) -> StateClient {
        StateClient(self.0.clone())
    }

    /// Server communication configuration operations
    pub fn server_communication_config(
        &self,
        repository: Arc<dyn server_communication_config::ServerCommunicationConfigRepositoryTrait>,
        platform_api: Arc<
            dyn bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi,
        >,
    ) -> Arc<server_communication_config::UniffiServerCommunicationConfigClient> {
        server_communication_config::UniffiServerCommunicationConfigClient::new(
            repository,
            platform_api,
        )
    }
}

#[derive(uniffi::Object)]
pub struct StateClient(Client);

#[derive(uniffi::Record)]
pub struct SqliteConfiguration {
    db_name: String,
    folder_path: String,
}

bitwarden_pm::create_client_managed_repositories!(Repositories, create_uniffi_repositories);

#[uniffi::export]
impl StateClient {
    #[deprecated(note = "Use `register_client_managed_repositories` instead")]
    pub fn register_cipher_repository(&self, repository: Arc<dyn CipherRepository>) {
        let cipher = UniffiRepositoryBridge::new(repository);
        self.0.platform().state().register_client_managed(cipher);
    }

    pub fn register_client_managed_repositories(&self, repositories: Repositories) {
        repositories.register_all(&self.0.platform().state());
    }

    /// Initialize the database for SDK managed repositories.
    pub async fn initialize_state(&self, configuration: SqliteConfiguration) -> Result<()> {
        let migrations = bitwarden_pm::migrations::get_sdk_managed_migrations();

        self.0
            .platform()
            .state()
            .initialize_database(configuration.into(), migrations)
            .await?;

        Ok(())
    }
}

impl From<SqliteConfiguration> for DatabaseConfiguration {
    fn from(config: SqliteConfiguration) -> Self {
        DatabaseConfiguration::Sqlite {
            db_name: config.db_name,
            folder_path: config.folder_path.into(),
        }
    }
}
