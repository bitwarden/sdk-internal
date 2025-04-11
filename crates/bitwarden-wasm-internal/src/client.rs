extern crate console_error_panic_hook;
use std::{fmt::Display, rc::Rc, sync::Arc};

use bitwarden_core::{client::internal::CipherStore, Client, ClientSettings};
use bitwarden_error::bitwarden_error;
use bitwarden_vault::Cipher;
use js_sys::{Array, JsString, Promise};
use tokio::sync::{mpsc, oneshot};
use wasm_bindgen::prelude::*;

use crate::{CryptoClient, VaultClient};

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
pub struct StoreClient(Rc<Client>);

impl StoreClient {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[derive(Debug, Clone)]
pub struct ChannelCipherStore {
    sender: mpsc::Sender<StoreCommand>,
}

pub enum StoreCommand {
    Get {
        id: String,
        respond_to: oneshot::Sender<Option<String>>,
    },
    List {
        respond_to: oneshot::Sender<Vec<String>>,
    },
    Set {
        id: String,
        value: String,
    },
    Remove {
        id: String,
    },
}

#[async_trait::async_trait]
impl CipherStore for ChannelCipherStore {
    async fn get(&self, id: &str) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        let cmd = StoreCommand::Get {
            id: id.to_string(),
            respond_to: tx,
        };
        let _ = self.sender.send(cmd).await;
        rx.await.expect("")
    }

    async fn list(&self) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        let cmd = StoreCommand::List { respond_to: tx };
        let _ = self.sender.send(cmd).await;
        rx.await.expect("")
    }

    async fn set(&self, id: &str, value: String) {
        let cmd = StoreCommand::Set {
            id: id.to_string(),
            value,
        };
        self.sender.send(cmd).await.expect("");
    }

    async fn remove(&self, id: &str) {
        let cmd = StoreCommand::Remove { id: id.to_string() };
        self.sender.send(cmd).await.expect("");
    }
}

#[wasm_bindgen(typescript_custom_section)]
const CIPHER_STORE_CUSTOM_TS_TYPE: &'static str = r#"
export interface CipherStore {
    get(id: string): Promise<string | null>;
    list(): Promise<string[]>;
    set(id: string, value: string): Promise<void>;
    remove(id: string): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = CipherStore, typescript_type = "CipherStore")]
    pub type JSCipherStore;

    #[wasm_bindgen(method)]
    async fn get(this: &JSCipherStore, id: String) -> JsValue;

    #[wasm_bindgen(method)]
    async fn list(this: &JSCipherStore) -> Array;

    #[wasm_bindgen(method)]
    async fn set(this: &JSCipherStore, id: String, value: String);

    #[wasm_bindgen(method)]
    async fn remove(this: &JSCipherStore, id: String);
}

#[wasm_bindgen]
impl StoreClient {
    pub async fn print_the_ciphers(&self) -> String {
        let store = self.0.internal.get_cipher_store().expect("msg");
        let mut result = String::new();
        let ciphers = store.list().await;
        for cipher in ciphers {
            result.push_str(&cipher);
            result.push('\n');
        }
        result
    }

    pub fn register_cipher_store(
        &self,
        store: JSCipherStore,
        //  get: js_sys::Function,
        //  list: js_sys::Function,
        //  save: js_sys::Function,
        //  delete: js_sys::Function,
    ) {
        let (tx, mut rx) = mpsc::channel::<StoreCommand>(32);

        wasm_bindgen_futures::spawn_local(async move {
            fn resolve_value(val: JsValue) -> Option<JsValue> {
                if val.is_null() || val.is_undefined() {
                    None
                } else {
                    Some(val)
                }
            }

            while let Some(cmd) = rx.recv().await {
                match cmd {
                    StoreCommand::Get { id, respond_to } => {
                        let result = store.get(id).await;
                        let result = resolve_value(result).map(|v| v.try_into().expect(""));
                        let _ = respond_to.send(result);
                    }
                    StoreCommand::List { respond_to } => {
                        let result = store.list().await;

                        let result: Vec<String> = result
                            .into_iter()
                            .map(|v| v.as_string().expect("msg"))
                            .collect();

                        let _ = respond_to.send(result);
                    }
                    StoreCommand::Set { id, value } => {
                        store.set(id, value).await;
                    }
                    StoreCommand::Remove { id } => {
                        store.remove(id).await;
                    }
                }
            }
        });

        let store = ChannelCipherStore { sender: tx };

        self.0.internal.register_cipher_store(Arc::new(store));
    }
}
