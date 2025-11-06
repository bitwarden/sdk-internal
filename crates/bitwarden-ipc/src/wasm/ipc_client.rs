use std::{collections::HashMap, sync::Arc};

use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use wasm_bindgen::prelude::*;

use super::communication_backend::JsCommunicationBackend;
use crate::{
    IpcClient,
    ipc_client::{IpcClientSubscription, ReceiveError, SubscribeError},
    message::{IncomingMessage, OutgoingMessage},
    traits::{InMemorySessionRepository, NoEncryptionCryptoProvider},
    wasm::{
        JsSessionRepository, RawJsSessionRepository,
        generic_session_repository::GenericSessionRepository,
    },
};

/// JavaScript wrapper around the IPC client. For more information, see the
/// [IpcClient] documentation.
#[wasm_bindgen(js_name = IpcClient)]
pub struct JsIpcClient {
    #[wasm_bindgen(skip)]
    /// The underlying IPC client instance. Use this to create WASM-compatible functions
    /// that interact with the IPC client, e.g. to register RPC handlers, trigger RPC requests,
    /// send typed messages, etc. For examples see
    /// [wasm::ipc_register_discover_handler](crate::wasm::ipc_register_discover_handler).
    pub client: Arc<
        IpcClient<NoEncryptionCryptoProvider, JsCommunicationBackend, GenericSessionRepository>,
    >,
    // Arc<IpcClient<NoEncryptionCryptoProvider, JsCommunicationBackend, JsSessionRepository>>,
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
    /// Create a new `IpcClient` instance with an in-memory session repository for saving
    /// sessions within the SDK.
    #[wasm_bindgen(js_name = newWithSdkInMemorySessions)]
    pub fn new_with_sdk_in_memory_sessions(
        communication_provider: &JsCommunicationBackend,
    ) -> JsIpcClient {
        JsIpcClient {
            client: IpcClient::new(
                NoEncryptionCryptoProvider,
                communication_provider.clone(),
                GenericSessionRepository::InMemory(Arc::new(InMemorySessionRepository::new(
                    HashMap::new(),
                ))),
            ),
        }
    }
    /// Create a new `IpcClient` instance with a client-managed session repository for saving
    /// sessions using State Provider.
    #[wasm_bindgen(js_name = newWithClientManagedSessions)]
    pub fn new_with_client_managed_sessions(
        communication_provider: &JsCommunicationBackend,
        session_repository: RawJsSessionRepository,
    ) -> JsIpcClient {
        JsIpcClient {
            client: IpcClient::new(
                NoEncryptionCryptoProvider,
                communication_provider.clone(),
                GenericSessionRepository::JsSessionRepository(Arc::new(JsSessionRepository::new(
                    session_repository,
                ))),
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
