extern crate console_error_panic_hook;
use std::fmt::Display;

use bitwarden_core::{key_management::CryptoClient, Client, ClientSettings};
use bitwarden_error::bitwarden_error;
use bitwarden_exporters::ExporterClientExt;
use bitwarden_generators::GeneratorClientsExt;
use bitwarden_vault::{VaultClient, VaultClientExt};
use wasm_bindgen::prelude::*;

use crate::platform::PlatformClient;

#[allow(missing_docs)]
#[wasm_bindgen]
pub struct BitwardenClient(pub(crate) Client);

#[wasm_bindgen]
impl BitwardenClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self(Client::new(settings))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    #[allow(missing_docs)]
    pub fn version(&self) -> String {
        env!("SDK_VERSION").to_owned()
    }

    #[allow(missing_docs)]
    pub fn throw(&self, msg: String) -> Result<(), TestError> {
        Err(TestError(msg))
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String, String> {
        let client = self.0.internal.get_http_client();
        let res = client.get(&url).send().await.map_err(|e| e.to_string())?;

        res.text().await.map_err(|e| e.to_string())
    }

    #[allow(missing_docs)]
    pub fn crypto(&self) -> CryptoClient {
        self.0.crypto()
    }

    #[allow(missing_docs)]
    pub fn vault(&self) -> VaultClient {
        self.0.vault()
    }

    /// Constructs a specific client for platform-specific functionality
    pub fn platform(&self) -> PlatformClient {
        PlatformClient::new(self.0.clone())
    }

    /// Constructs a specific client for generating passwords and passphrases
    pub fn generator(&self) -> bitwarden_generators::GeneratorClient {
        self.0.generator()
    }

    #[allow(missing_docs)]
    pub fn exporters(&self) -> bitwarden_exporters::ExporterClient {
        self.0.exporters()
    }
}

#[bitwarden_error(basic)]
pub struct TestError(String);

impl Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
