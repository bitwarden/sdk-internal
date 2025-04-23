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
    /// It returns an [Account Entity](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html#entity-account)
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
    /// It expects an [Account Entity](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html#entity-account) serialized as a JSON string.
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>, ExportError> {
        self.0.exporters().import_cxf(payload)
    }
}
