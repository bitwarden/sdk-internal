use wasm_bindgen::prelude::*;

use crate::{
    message::Message,
    providers::{InMemorySessionProvider, NoEncryptionCryptoProvider},
    Manager,
};

use super::{
    communication::JsCommunicationProvider,
    error::{JsReceiveError, JsSendError},
};

#[wasm_bindgen(js_name = Manager)]
pub struct JsManager {
    // TODO: Change session provider to a JS-implemented one
    manager:
        Manager<NoEncryptionCryptoProvider, JsCommunicationProvider, InMemorySessionProvider<()>>,
}

#[wasm_bindgen(js_class = Manager)]
impl JsManager {
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: JsCommunicationProvider) -> JsManager {
        JsManager {
            manager: Manager::new(
                NoEncryptionCryptoProvider,
                communication_provider,
                InMemorySessionProvider::new(),
            ),
        }
    }

    pub async fn send(&self, message: Message) -> Result<(), JsSendError> {
        self.manager.send(message).await.map_err(|e| e.into())
    }

    pub async fn receive(&self) -> Result<Message, JsReceiveError> {
        self.manager.receive().await.map_err(|e| e.into())
    }
}
