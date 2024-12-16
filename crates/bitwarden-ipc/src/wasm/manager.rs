use wasm_bindgen::prelude::*;

use crate::{destination::Destination, providers::NoEncryptionCryptoProvider, Manager};

use super::link::JsLink;

#[wasm_bindgen(js_name = Manager)]
pub struct JsManager {
    // TODO: This can't be generic because of wasm_bindgen
    manager: Manager<NoEncryptionCryptoProvider>,
}

#[wasm_bindgen]
impl JsManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsManager {
        JsManager {
            manager: Manager::new(NoEncryptionCryptoProvider),
        }
    }

    pub fn register_link(&mut self, link: JsLink) {
        self.manager.register_link(Box::new(link));
    }

    pub fn get_channel(&self, _destination: Destination) {
        todo!()
    }
}
