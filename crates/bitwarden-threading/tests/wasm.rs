use bitwarden_threading::ThreadBoundRunner;
use serde::{Deserialize, Serialize};
use tsify_next::{serde_wasm_bindgen, Tsify};
use wasm_bindgen::prelude::*;

#[async_trait::async_trait]
trait Store<T> {
    async fn get(&self, id: String) -> T;
    async fn save(&self, item: T);
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
struct Cipher {
    id: String,
    name: String,
    password: String,
}

#[wasm_bindgen]
extern "C" {
    pub type CipherService;

    #[wasm_bindgen(constructor)]
    pub fn new() -> CipherService;

    #[wasm_bindgen(method)]
    pub async fn get(this: &CipherService, id: String) -> JsValue;

    #[wasm_bindgen(method)]
    pub async fn save(this: &CipherService, cipher: Cipher);
}

#[tokio::test]
pub async fn test_wasm() {
    let obj = CipherService::new();
    assert!(obj.is_instance_of::<CipherService>());
}

#[tokio::test]
pub async fn test_get_cipher() {
    let cipher_service = CipherService::new();
    let bound_cipher_service = ThreadBoundRunner::new(cipher_service);

    struct CipherStore(ThreadBoundRunner<CipherService>);

    #[async_trait::async_trait]
    impl Store<Cipher> for CipherStore {
        async fn get(&self, id: String) -> Cipher {
            self.0
                .run_in_thread(move |state| {
                    Box::pin(async move {
                        let js_value_cipher = state.get(id).await;
                        let cipher: Cipher = serde_wasm_bindgen::from_value(js_value_cipher)
                            .expect("Failed to convert JsValue to Cipher");
                        cipher
                    })
                })
                .await
                .unwrap()
        }

        async fn save(&self, item: Cipher) {
            self.0
                .run_in_thread(move |state| {
                    Box::pin(async move {
                        state.save(item).await;
                    })
                })
                .await
                .unwrap();
        }
    }

    let store = CipherStore(bound_cipher_service);
    let cipher = store.get("some-cipher".to_owned()).await;
    store.save(cipher).await;
}
