use bitwarden_collections::collection::Collection;
use bitwarden_core::Client;
use bitwarden_vault::{Cipher, EncryptionContext, Folder};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Account, ExportError, ExportFormat,
    export::{export_cxf, export_organization_vault, export_vault, import_cxf},
};

#[allow(missing_docs)]
#[bitwarden_ffi::wasm_object]
pub struct ExporterClient {
    client: Client,
}

#[bitwarden_ffi::wasm_export]
impl ExporterClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub async fn export_vault(
        &self,
        folders: Vec<Folder>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String, ExportError> {
        export_vault(&self.client, folders, ciphers, format).await
    }

    #[allow(missing_docs)]
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
    /// Ideally, the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn export_cxf(
        &self,
        account: Account,
        ciphers: Vec<Cipher>,
    ) -> Result<String, ExportError> {
        export_cxf(&self.client, account, ciphers)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally, the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    ///
    /// Each returned [`EncryptionContext`] carries the encrypted cipher along with the user it was
    /// encrypted for and the id of the key it was wrapped under.
    pub fn import_cxf(&self, payload: String) -> Result<Vec<EncryptionContext>, ExportError> {
        import_cxf(&self.client, payload)
    }
}

#[allow(missing_docs)]
pub trait ExporterClientExt {
    fn exporters(&self) -> ExporterClient;
}

impl ExporterClientExt for Client {
    fn exporters(&self) -> ExporterClient {
        ExporterClient::new(self.clone())
    }
}
