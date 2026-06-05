use bitwarden_collections::collection::Collection;
use bitwarden_core::Client;
use bitwarden_vault::{Cipher, Folder};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Account, ExportError, ExportFormat, KdbxImportResult,
    export::{export_cxf, export_organization_vault, export_vault, import_cxf, import_kdbx},
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ExporterClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
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
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>, ExportError> {
        import_cxf(&self.client, payload)
    }

    /// Import a KeePass KDBX (`.kdbx`) database.
    ///
    /// `file` is the raw `.kdbx` bytes; `password` and/or `key_file` unlock it. Returns the
    /// encrypted ciphers and folders plus their relationships, ready to send to the import
    /// endpoint.
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    pub fn import_kdbx(
        &self,
        file: Vec<u8>,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
    ) -> Result<KdbxImportResult, ExportError> {
        import_kdbx(&self.client, file, password, key_file)
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
