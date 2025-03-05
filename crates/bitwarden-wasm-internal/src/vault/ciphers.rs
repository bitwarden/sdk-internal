use std::rc::Rc;

use bitwarden_core::Client;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct ClientCiphers(Rc<Client>);

impl ClientCiphers {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientCiphers {}
