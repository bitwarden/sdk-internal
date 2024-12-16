use std::sync::Arc;

use bitwarden_exporters::{Account, ClientExportersExt, ExportFormat};
use bitwarden_generators::{
    ClientGeneratorExt, PassphraseGeneratorRequest, PasswordGeneratorRequest,
    UsernameGeneratorRequest,
};
use bitwarden_vault::{Cipher, Collection, Folder};

use crate::{
    error::{Error, Result},
    Client,
};

mod sends;
pub use sends::ClientSends;

#[derive(uniffi::Object)]
pub struct ClientGenerators(pub(crate) Arc<Client>);

#[uniffi::export(async_runtime = "tokio")]
impl ClientGenerators {
    /// Generate Password
    pub fn password(&self, settings: PasswordGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .password(settings)
            .map_err(Error::PasswordError)?)
    }

    /// Generate Passphrase
    pub fn passphrase(&self, settings: PassphraseGeneratorRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .generator()
            .passphrase(settings)
            .map_err(Error::PassphraseError)?)
    }

    /// Generate Username
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
pub struct ClientExporters(pub(crate) Arc<Client>);

#[uniffi::export]
impl ClientExporters {
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
            .map_err(Error::ExportError)?)
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
            .map_err(Error::ExportError)?)
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
            .map_err(Error::ExportError)?)
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
            .map_err(Error::ExportError)?)
    }
}
