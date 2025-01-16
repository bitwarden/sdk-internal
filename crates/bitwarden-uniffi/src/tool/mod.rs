use std::sync::Arc;

use bitwarden_exporters::{Account, ExportFormat, ExporterClientExt};
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
pub use sends::SendClient;

mod ssh;
pub use ssh::SshClient;

#[derive(uniffi::Object)]
pub struct GeneratorClients(pub(crate) Arc<Client>);

#[uniffi::export(async_runtime = "tokio")]
impl GeneratorClients {
    /// Generate Password
    pub fn password(&self, settings: PasswordGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .password(settings)
            .map_err(Error::Password)?)
    }

    /// Generate Passphrase
    pub fn passphrase(&self, settings: PassphraseGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .passphrase(settings)
            .map_err(Error::Passphrase)?)
    }

    /// Generate Username
    pub async fn username(&self, settings: UsernameGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .username(settings)
            .await
            .map_err(Error::Username)?)
    }
}

#[derive(uniffi::Object)]
pub struct ExporterClient(pub(crate) Arc<Client>);

#[uniffi::export]
impl ExporterClient {
    /// Export user vault
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
            .map_err(Error::Export)?)
    }

    /// Export organization vault
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
            .map_err(Error::Export)?)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the output should be immediately deserialized to [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn export_cxf(&self, account: Account, ciphers: Vec<Cipher>) -> Result<String> {
        Ok(self
            .0
             .0
            .exporters()
            .export_cxf(account, ciphers)
            .map_err(Error::Export)?)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>> {
        Ok(self
            .0
             .0
            .exporters()
            .import_cxf(payload)
            .map_err(Error::Export)?)
    }
}
