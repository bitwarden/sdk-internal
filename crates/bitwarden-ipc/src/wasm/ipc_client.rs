use std::{collections::HashMap, sync::Arc};

use wasm_bindgen::prelude::*;

use super::{communication_backend::JsCommunicationBackend, ThreadSafeJsCommunicationBackend};
use crate::{
    ipc_client::{IpcClientSubscription, ReceiveError, StartError, SubscribeError},
    message::{IncomingMessage, OutgoingMessage},
    traits::{InMemorySessionRepository, NoEncryptionCryptoProvider},
    IpcClient,
};

#[wasm_bindgen(js_name = IpcClient)]
pub struct JsIpcClient {
    // TODO: Change session provider to a JS-implemented one
    client: Arc<
        IpcClient<
            NoEncryptionCryptoProvider,
            ThreadSafeJsCommunicationBackend,
            InMemorySessionRepository<()>,
        >,
    >,
}

#[wasm_bindgen(js_name = IpcClientSubscription)]
pub struct JsIpcClientSubscription {
    subscription: IpcClientSubscription<
        NoEncryptionCryptoProvider,
        ThreadSafeJsCommunicationBackend,
        InMemorySessionRepository<()>,
    >,
}

#[wasm_bindgen(js_class = IpcClientSubscription)]
impl JsIpcClientSubscription {
    pub async fn receive(&mut self) -> Result<IncomingMessage, ReceiveError> {
        self.subscription.receive(None).await.map_err(|e| e.into())
    }
}

#[wasm_bindgen(js_class = IpcClient)]
impl JsIpcClient {
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: &JsCommunicationBackend) -> JsIpcClient {
        let communication_provider: ThreadSafeJsCommunicationBackend =
            communication_provider.into();
        JsIpcClient {
            client: IpcClient::new(
                NoEncryptionCryptoProvider,
                communication_provider,
                InMemorySessionRepository::new(HashMap::new()),
            ),
        }
    }

    pub async fn start(&self) -> Result<(), StartError> {
        self.client.start().await
    }

    #[wasm_bindgen(js_name = isRunning)]
    pub async fn is_running(&self) -> bool {
        self.client.is_running().await
    }

    pub async fn send(&self, message: OutgoingMessage) -> Result<(), JsError> {
        self.client
            .send(message)
            .await
            .map_err(|e| JsError::new(&e))
    }

    pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> {
        let subscription = self.client.subscribe(None).await?;
        Ok(JsIpcClientSubscription { subscription })
    }
}
