use std::{collections::HashMap, sync::Arc};

use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use wasm_bindgen::prelude::*;

use super::communication_backend::JsCommunicationBackend;
use crate::{
    ipc_client::{IpcClientSubscription, ReceiveError, SubscribeError},
    message::{IncomingMessage, OutgoingMessage},
    traits::{InMemorySessionRepository, NoEncryptionCryptoProvider},
    IpcClient,
};

/// JavaScript wrapper around the IPC client. For more information, see the
/// [IpcClient] documentation.
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

/// JavaScript wrapper around the IPC client subscription. For more information, see the
/// [IpcClientSubscription](crate::IpcClientSubscription) documentation.
#[wasm_bindgen(js_name = IpcClientSubscription)]
pub struct JsIpcClientSubscription {
    subscription: IpcClientSubscription,
}

#[wasm_bindgen(js_class = IpcClientSubscription)]
impl JsIpcClientSubscription {
    #[allow(missing_docs)]
    pub async fn receive(
        &mut self,
        abort_signal: Option<AbortSignal>,
    ) -> Result<IncomingMessage, ReceiveError> {
        let cancellation_token = abort_signal.map(|signal| signal.to_cancellation_token());
        self.subscription.receive(cancellation_token).await
    }
}

#[wasm_bindgen(js_class = IpcClient)]
impl JsIpcClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(communication_provider: &JsCommunicationBackend) -> JsIpcClient {
        JsIpcClient {
            client: IpcClient::new(
                NoEncryptionCryptoProvider,
                communication_provider.clone(),
                InMemorySessionRepository::new(HashMap::new()),
            ),
        }
    }

    #[allow(missing_docs)]
    pub async fn start(&self) {
        self.client.start().await
    }

    #[wasm_bindgen(js_name = isRunning)]
    #[allow(missing_docs)]
    pub async fn is_running(&self) -> bool {
        self.client.is_running().await
    }

    #[allow(missing_docs)]
    pub async fn send(&self, message: OutgoingMessage) -> Result<(), JsError> {
        self.client
            .send(message)
            .await
            .map_err(|e| JsError::new(&e))
    }

    #[allow(missing_docs)]
    pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> {
        let subscription = self.client.subscribe(None).await?;
        Ok(JsIpcClientSubscription { subscription })
    }
}
