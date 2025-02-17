use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use crate::{
    message::Message,
    traits::{InMemorySessionRepository, NoEncryptionCryptoProvider},
    Manager,
};

use super::{
    communication::JsCommunicationBackend,
    error::{JsReceiveError, JsSendError},
};

#[wasm_bindgen(js_name = Manager)]
pub struct JsManager {
    // TODO: Change session provider to a JS-implemented one
    manager:
        Manager<NoEncryptionCryptoProvider, JsCommunicationBackend, InMemorySessionRepository<()>>,
}

#[wasm_bindgen(js_class = Manager)]
impl JsManager {
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: JsCommunicationBackend) -> JsManager {
        JsManager {
            manager: Manager::new(
                NoEncryptionCryptoProvider,
                communication_provider,
                InMemorySessionRepository::new(HashMap::new()),
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
