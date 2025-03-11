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

/// The type of the IpcClient that will be used in the JS code. Use this to create
/// typed wrappers around the IpcClient that can be used from JS.
pub type WasmIpcClient =
    IpcClient<NoEncryptionCryptoProvider, JsCommunicationBackend, InMemorySessionRepository<()>>;

/// A wrapper around the IpcClient that can be used from JS, don't use this directly
/// in Rust code.
#[wasm_bindgen(js_name = IpcClient)]
pub struct JsIpcClientWrapper {
    // TODO: Change session provider to a JS-implemented one
    client: IpcClient<
        NoEncryptionCryptoProvider,
        JsCommunicationBackend,
        InMemorySessionRepository<()>,
    >,
}

#[wasm_bindgen(js_class = IpcClient)]
impl JsIpcClientWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: JsCommunicationBackend) -> JsIpcClientWrapper {
        JsIpcClientWrapper {
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
