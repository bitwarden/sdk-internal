use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use super::{
    communication_backend::JsCommunicationBackend,
    error::{JsReceiveError, JsSendError},
};
use crate::{
    message::{IncomingMessage, OutgoingMessage},
    traits::{InMemorySessionRepository, NoEncryptionCryptoProvider},
    IpcClient,
};

#[wasm_bindgen(js_name = IpcClient)]
pub struct JsIpcClient {
    // TODO: Change session provider to a JS-implemented one
    client: IpcClient<
        NoEncryptionCryptoProvider,
        JsCommunicationBackend,
        InMemorySessionRepository<()>,
    >,
}

#[wasm_bindgen(js_class = IpcClient)]
impl JsIpcClient {
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: JsCommunicationBackend) -> JsIpcClient {
        JsIpcClient {
            client: IpcClient::new(
                NoEncryptionCryptoProvider,
                communication_provider,
                InMemorySessionRepository::new(HashMap::new()),
            ),
        }
    }

    pub async fn send(&self, message: OutgoingMessage) -> Result<(), JsSendError> {
        self.client.send(message).await.map_err(|e| e.into())
    }

    pub async fn receive(&self) -> Result<IncomingMessage, JsReceiveError> {
        self.client.receive().await.map_err(|e| e.into())
    }
}
