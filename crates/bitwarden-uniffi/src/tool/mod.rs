use std::sync::Arc;

use bitwarden_exporters::{ExportFormat, ExporterClientsExt};
use bitwarden_generators::{
    GeneratorClientsExt, PassphraseGeneratorRequest, PasswordGeneratorRequest,
    UsernameGeneratorRequest,
};
use bitwarden_vault::{Cipher, Collection, Folder};

use crate::{
    error::{Error, Result},
    Client,
};

mod sends;
pub use sends::SendClients;

#[derive(uniffi::Object)]
pub struct GeneratorClients(pub(crate) Arc<Client>);

#[uniffi::export(async_runtime = "tokio")]
impl GeneratorClients {
    /// **API Draft:** Generate Password
    pub fn password(&self, settings: PasswordGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .password(settings)
            .map_err(Error::PasswordError)?)
    }

    /// **API Draft:** Generate Passphrase
    pub fn passphrase(&self, settings: PassphraseGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .passphrase(settings)
            .map_err(Error::PassphraseError)?)
    }

    /// **API Draft:** Generate Username
    pub async fn username(&self, settings: UsernameGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .username(settings)
            .await
            .map_err(Error::UsernameError)?)
    }
}

#[derive(uniffi::Object)]
pub struct ExporterClients(pub(crate) Arc<Client>);

#[uniffi::export]
impl ExporterClients {
    /// **API Draft:** Export user vault
    pub fn export_vault(
        &self,
        folders: Vec<Folder>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String> {
        Ok(self
            .0
             .0
            .exporters()
            .export_vault(folders, ciphers, format)
            .map_err(Error::ExportError)?)
    }

    /// **API Draft:** Export organization vault
    pub fn export_organization_vault(
        &self,
        collections: Vec<Collection>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String> {
        Ok(self
            .0
             .0
            .exporters()
            .export_organization_vault(collections, ciphers, format)
            .map_err(Error::ExportError)?)
    }
}
