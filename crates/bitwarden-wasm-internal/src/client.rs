extern crate console_error_panic_hook;
use std::{fmt::Display, sync::Arc};

use bitwarden_core::{client::data_store::DataStore, Client, ClientSettings};
use bitwarden_error::bitwarden_error;
use bitwarden_vault::Cipher;
use bitwarden_vault::VaultClientExt;
use tokio::sync::mpsc;
use tsify_next::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::{CryptoClient, GeneratorClient, VaultClient};

#[wasm_bindgen]
pub struct BitwardenClient(pub(crate) Client);

#[wasm_bindgen]
impl BitwardenClient {
    #[wasm_bindgen(constructor)]
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self(Client::new(settings))
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
        CryptoClient::new(self.0.crypto())
    }

    pub fn vault(&self) -> VaultClient {
        VaultClient::new(self.0.vault())
    }

    /// Constructs a specific client for generating passwords and passphrases
    pub fn generator(&self) -> GeneratorClient {
        GeneratorClient::new(self.0.clone())
    }

    pub fn store(&self) -> StoreClient {
        StoreClient::new(self.0.clone())
    }
}

#[bitwarden_error(basic)]
pub struct TestError(String);

impl Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[wasm_bindgen]
pub struct StoreClient(Client);

impl StoreClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const CIPHER_STORE_CUSTOM_TS_TYPE: &'static str = r#"
export interface CipherStore {
    get(id: string): Promise<Cipher | null>;
    list(): Promise<Cipher[]>;
    set(id: string, value: Cipher): Promise<void>;
    remove(id: string): Promise<void>;
}
"#;

#[bitwarden_ffi_macros::extern_wasm_channel(trait_impl = "DataStore<Cipher>", async_trait = true)]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = CipherStore, typescript_type = "CipherStore")]
    pub type JSCipherStore;

    #[wasm_bindgen(method)]
    async fn get(this: &JSCipherStore, id: String) -> Option<Cipher>;

    #[wasm_bindgen(method)]
    async fn list(this: &JSCipherStore) -> Vec<Cipher>;

    #[wasm_bindgen(method)]
    async fn set(this: &JSCipherStore, id: String, value: Cipher);

    #[wasm_bindgen(method)]
    async fn remove(this: &JSCipherStore, id: String);
}

#[wasm_bindgen]
impl StoreClient {
    pub async fn print_the_ciphers(&self) -> String {
        let store = self.0.internal.get_data_store::<Cipher>().expect("msg");
        let mut result = String::new();
        let ciphers = store.list().await;
        for cipher in ciphers {
            result.push_str(format!("{:?}", cipher).as_str());
            result.push('\n');
        }
        result
    }

    pub fn register_cipher_store(&self, store: JSCipherStore) {
        let store = store.create_channel_impl();
        self.0.internal.register_data_store(Arc::new(store));
    }
}
