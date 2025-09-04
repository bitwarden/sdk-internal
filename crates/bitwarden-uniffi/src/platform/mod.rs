use std::sync::Arc;

use bitwarden_core::{platform::FingerprintRequest, Client};
use bitwarden_fido::ClientFido2Ext;
use bitwarden_state::{repository::RepositoryItem, DatabaseConfiguration};
use bitwarden_vault::Cipher;
use repository::UniffiRepositoryBridge;

use crate::error::{Error, Result};

mod fido2;
mod repository;

#[derive(uniffi::Object)]
pub struct PlatformClient(pub(crate) bitwarden_core::Client);

#[uniffi::export]
impl PlatformClient {
    /// Fingerprint (public key)
    pub fn fingerprint(&self, req: FingerprintRequest) -> Result<String> {
        Ok(self
            .0
            .platform()
            .fingerprint(&req)
            .map_err(Error::Fingerprint)?)
    }

    /// Fingerprint using logged in user's public key
    pub fn user_fingerprint(&self, fingerprint_material: String) -> Result<String> {
        Ok(self
            .0
            .platform()
            .user_fingerprint(fingerprint_material)
            .map_err(Error::UserFingerprint)?)
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
}

#[derive(uniffi::Object)]
pub struct StateClient(Client);

repository::create_uniffi_repository!(CipherRepository, Cipher);

#[derive(uniffi::Record)]
pub struct SqliteConfiguration {
    db_name: String,
    folder_path: String,
}

#[uniffi::export]
impl StateClient {
    pub fn register_cipher_repository(&self, repository: Arc<dyn CipherRepository>) {
        let cipher = UniffiRepositoryBridge::new(repository);
        self.0.platform().state().register_client_managed(cipher);
    }

    pub async fn initialize_state(&self, configuration: SqliteConfiguration) -> Result<()> {
        let sdk_managed_repositories = vec![
            // This should list all the SDK-managed repositories
            <Cipher as RepositoryItem>::data(),
        ];

        self.0
            .platform()
            .state()
            .initialize_database(configuration.into(), sdk_managed_repositories)
            .await
            .map_err(Error::StateRegistry)?;
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
