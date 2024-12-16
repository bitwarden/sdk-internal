use bitwarden_core::Client;
use bitwarden_vault::{Cipher, Collection, Folder};

use crate::{
    export::{export_cxf, export_organization_vault, export_vault, import_cxf},
    Account, ExportError, ExportFormat,
};

pub struct ExporterClient<'a> {
    client: &'a Client,
}

impl<'a> ExporterClient<'a> {
    fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub fn export_vault(
        &self,
        folders: Vec<Folder>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String, ExportError> {
        export_vault(self.client, folders, ciphers, format)
    }

    pub fn export_organization_vault(
        &self,
        collections: Vec<Collection>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String, ExportError> {
        export_organization_vault(collections, ciphers, format)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn export_cxf(
        &self,
        account: Account,
        ciphers: Vec<Cipher>,
    ) -> Result<String, ExportError> {
        export_cxf(self.client, account, ciphers)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>, ExportError> {
        import_cxf(self.client, payload)
    }
}

pub trait ExporterClientExt<'a> {
    fn exporters(&'a self) -> ExporterClient<'a>;
}

impl<'a> ExporterClientExt<'a> for Client {
    fn exporters(&'a self) -> ExporterClient<'a> {
        ExporterClient::new(self)
    }
}
