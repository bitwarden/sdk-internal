use bitwarden_threading::ThreadBoundDispatcher;
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
    let bound_cipher_service = ThreadBoundDispatcher::new(cipher_service);

    struct CipherStore(ThreadBoundDispatcher<CipherService>);

    #[async_trait::async_trait]
    impl Store<Cipher> for CipherStore {
        async fn get(&self, id: String) -> Cipher {
            // self.0.type_id();
            self.0
                .call(move |state| {
                    let cipher = async {
                        let js_value_cipher = state.get(id).await;
                        let cipher: Cipher = serde_wasm_bindgen::from_value(js_value_cipher)
                            .expect("Failed to convert JsValue to Cipher");
                        cipher
                    };
                    Box::pin(async move { cipher.await })
                })
                .await
                .unwrap()
        }

        async fn save(&self, item: Cipher) {
            // self.call(move |state| Box::pin(async move { state.save(item) }))
            //     .await
            //     .unwrap();
        }
    }
}
