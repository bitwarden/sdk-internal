extern crate console_error_panic_hook;
use std::{fmt::Display, rc::Rc};

use bitwarden_core::{Client, ClientSettings};
use bitwarden_error::bitwarden_error;
use wasm_bindgen::prelude::*;

use crate::{crypto::{pure_crypto, PureCryptoError}, vault::VaultClient, CryptoClient};

#[wasm_bindgen]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

fn convert_level(level: LogLevel) -> Level {
    match level {
        LogLevel::Trace => Level::Trace,
        LogLevel::Debug => Level::Debug,
        LogLevel::Info => Level::Info,
        LogLevel::Warn => Level::Warn,
        LogLevel::Error => Level::Error,
    }
}

#[wasm_bindgen]
pub struct BitwardenPure;

#[wasm_bindgen]
impl BitwardenPure {
    pub fn version() -> String {
        Self::setup_once();
        env!("SDK_VERSION").to_owned()
    }

    pub fn echo(msg: String) -> String {
        Self::setup_once();
        msg
    }

    pub fn throw(msg: String) -> Result<(), TestError> {
        Self::setup_once();
        Err(TestError(msg))
    }

    pub fn symmetric_decrypt(enc_string: String, key_b64: String) -> Result<String, PureCryptoError> {
        Self::setup_once();
        Ok(pure_crypto::symmetric_decrypt(enc_string, key_b64)?)
    }

    pub fn symmetric_decrypt_to_bytes(
        enc_string: String,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        Self::setup_once();
        pure_crypto::symmetric_decrypt_to_bytes(enc_string, key_b64)
    }

    pub fn symmetric_encrypt(
        plain: String,
        key_b64: String,
    ) -> Result<String, PureCryptoError> {
        Self::setup_once();
        pure_crypto::symmetric_encrypt(plain, key_b64)
    }

    fn setup_once() {
        console_error_panic_hook::set_once();
        let log_level = convert_level(LogLevel::Info);
        if let Err(_e) = console_log::init_with_level(log_level) {
            set_max_level(log_level.to_level_filter())
        }
    }
}

// Rc<...> is to avoid needing to take ownership of the Client during our async run_command
// function https://github.com/rustwasm/wasm-bindgen/issues/2195#issuecomment-799588401
#[wasm_bindgen]
pub struct BitwardenClient(pub(crate) Rc<Client>);

#[wasm_bindgen]
impl BitwardenClient {
    #[wasm_bindgen(constructor)]
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self(Rc::new(Client::new(settings)))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    pub fn version(&self) -> String {
        env!("SDK_VERSION").to_owned()
    }

    pub fn throw(&self, msg: String) -> Result<(), TestError> {
        Err(TestError(msg))
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String, String> {
        let client = self.0.internal.get_http_client();
        let res = client.get(&url).send().await.map_err(|e| e.to_string())?;

        res.text().await.map_err(|e| e.to_string())
    }

    pub fn crypto(&self) -> CryptoClient {
        CryptoClient::new(self.0.clone())
    }

    pub fn vault(&self) -> VaultClient {
        VaultClient::new(self.0.clone())
    }
}

#[bitwarden_error(basic)]
pub struct TestError(String);

impl Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
