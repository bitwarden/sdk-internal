use bitwarden_threading::ThreadBoundRunner;
use serde::{Deserialize, Serialize};
use tsify::{Tsify, serde_wasm_bindgen};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[async_trait::async_trait]
trait Store<T> {
    async fn get(&self, id: String) -> T;
    async fn save(&self, item: T);
}

#[derive(Clone, Debug, Tsify, Serialize, Deserialize, PartialEq, Eq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
struct Cipher {
    id: String,
    name: String,
    password: String,
}

#[wasm_bindgen(inline_js = "export class CipherService {
    constructor() {
        this.ciphers = {};
    }

    async get(id) {
        return this.ciphers[id];
    }

    async save(cipher) {
        this.ciphers[cipher.id] = cipher;
    }
}")]
extern "C" {
    pub type CipherService;

    #[wasm_bindgen(constructor)]
    pub fn new() -> CipherService;

    #[wasm_bindgen(method)]
    pub async fn get(this: &CipherService, id: String) -> JsValue;

    #[wasm_bindgen(method)]
    pub async fn save(this: &CipherService, cipher: Cipher);
}

#[wasm_bindgen_test]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
pub async fn test_get_cipher() {
    console_error_panic_hook::set_once();

    let cipher_service = CipherService::new();
    let bound_cipher_service = ThreadBoundRunner::new(cipher_service);

    struct CipherStore(ThreadBoundRunner<CipherService>);

    #[async_trait::async_trait]
    impl Store<Cipher> for CipherStore {
        async fn get(&self, id: String) -> Cipher {
            self.0
                .run_in_thread(|state| async move {
                    let js_value_cipher = state.get(id).await;
                    let cipher: Cipher = serde_wasm_bindgen::from_value(js_value_cipher)
                        .expect("Failed to convert JsValue to Cipher");
                    cipher
                })
                .await
                .expect("Failed to get cipher")
        }

        async fn save(&self, item: Cipher) {
            self.0
                .run_in_thread(|state| async move {
                    state.save(item).await;
                })
                .await
                .expect("Failed to save cipher");
        }
    }

    let store = CipherStore(bound_cipher_service);
    let cipher = Cipher {
        id: "id".to_owned(),
        name: "name".to_owned(),
        password: "password".to_owned(),
    };

    store.save(cipher.clone()).await;
    let result = store.get("id".to_owned()).await;

    assert_eq!(result, cipher);
}
