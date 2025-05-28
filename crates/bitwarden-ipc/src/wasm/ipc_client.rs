use std::{collections::HashMap, sync::Arc};

use wasm_bindgen::prelude::*;

use super::{
    communication_backend::JsCommunicationBackend,
    error::{JsReceiveError, JsSendError},
};
use crate::{
    ipc_client::IpcClientSubscription,
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
            JsCommunicationBackend,
            InMemorySessionRepository<()>,
        >,
    >,
}

#[wasm_bindgen(js_name = IpcClientSubscription)]
pub struct JsIpcClientSubscription {
    subscription: IpcClientSubscription<
        NoEncryptionCryptoProvider,
        JsCommunicationBackend,
        InMemorySessionRepository<()>,
    >,
}

#[wasm_bindgen(js_class = IpcClientSubscription)]
impl JsIpcClientSubscription {
    pub async fn receive(&self) -> Result<IncomingMessage, JsReceiveError> {
        self.subscription.receive(None).await.map_err(|e| e.into())
    }
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

    pub async fn subscribe(&self) -> JsIpcClientSubscription {
        let subscription = self.client.subscribe(None).await;
        JsIpcClientSubscription { subscription }
    }
}
