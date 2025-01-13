// use std::rc::Rc;

// use bitwarden_core::Client;
// use bitwarden_ipc::wasm::manager::JsManager;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct IpcClient;
// pub struct IpcClient(Rc<Client>);

// impl IpcClient {
//     pub fn new(client: Rc<Client>) -> Self {
//         Self(client)
//     }
// }

// #[wasm_bindgen]
// impl IpcClient {
//     // This function is technically not needed
//     // But if we don't include it then wasm-bindgen will not generate the JS bindings
//     pub fn create_manager(&self) -> JsManager {
//         JsManager::new()
//     }
// }
