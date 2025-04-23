use bitwarden_core::Client;
use bitwarden_exporters::{Account, ExportError, ExporterClientExt};
use bitwarden_vault::Cipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ExporterClient(Client);

impl ExporterClient {
    /// Constructs a new SDK client for exporting and importing vault items.
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ExporterClient {
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
        self.0.exporters().export_cxf(account, ciphers)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>, ExportError> {
        self.0.exporters().import_cxf(payload)
    }
}
