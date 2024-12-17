use wasm_bindgen::prelude::*;

use crate::{destination::Destination, providers::NoEncryptionCryptoProvider, Manager};

use super::link::JsLink;

#[wasm_bindgen(js_name = Manager)]
pub struct JsManager {
    // TODO: This can't be generic because of wasm_bindgen
    manager: Manager<NoEncryptionCryptoProvider, JsLink>,
}

#[wasm_bindgen(js_class = Manager)]
impl JsManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsManager {
        JsManager {
            manager: Manager::new(NoEncryptionCryptoProvider),
        }
    }

    pub fn register_link(&mut self, link: JsLink) {
        self.manager.register_link(link);
    }

    pub async fn send(&self, destination: Destination, data: &[u8]) {
        self.manager.send(destination, data).await;
    }

    pub async fn receive(&self, destination: Destination) -> Vec<u8> {
        self.manager.receive(destination).await
    }
}
