use std::{collections::HashMap, sync::Arc};

use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use super::communication_backend::JsCommunicationBackend;
use crate::{
    IpcClientImpl,
    broadcast::{BroadcastGroup, EndpointSendResult},
    crypto_provider::noise::crypto_provider::NoiseCryptoProvider,
    endpoint::Endpoint,
    error::{AlreadyRunningError, BroadcastError, ReceiveError, SendError, SubscribeError},
    ipc_client::IpcClientSubscription,
    ipc_client_trait::IpcClient,
    message::{IncomingMessage, OutgoingMessage},
    traits::InMemorySessionRepository,
    wasm::{
        JsSessionRepository, RawJsSessionRepository,
        generic_session_repository::GenericSessionRepository,
    },
};

/// JavaScript wrapper around the IPC client. For more information, see the
/// [`IpcClient`] trait documentation.
#[bitwarden_ffi::wasm_object(js_name = IpcClient)]
pub struct JsIpcClient {
    #[wasm_bindgen(skip)]
    /// The underlying IPC client instance. Use this to create WASM-compatible functions
    /// that interact with the IPC client, e.g. to register RPC handlers, trigger RPC requests,
    /// send typed messages, etc. For examples see
    /// [wasm::ipc_register_discover_handler](crate::wasm::ipc_register_discover_handler).
    pub client: Arc<dyn IpcClient>,
}

/// The outcome of delivering a broadcast message to one member of a [`BroadcastGroup`].
/// JavaScript counterpart of [`EndpointSendResult`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[bitwarden_ffi::wasm_record]
pub struct IpcEndpointSendResult {
    /// The endpoint the message was sent to.
    pub endpoint: Endpoint,
    /// Why the send to this endpoint failed. Absent if the send succeeded.
    pub error: Option<SendError>,
}

impl From<EndpointSendResult> for IpcEndpointSendResult {
    fn from(value: EndpointSendResult) -> Self {
        Self {
            endpoint: value.endpoint,
            error: value.result.err(),
        }
    }
}

/// JavaScript wrapper around the IPC client subscription. For more information, see the
/// [IpcClientSubscription](crate::IpcClientSubscription) documentation.
#[bitwarden_ffi::wasm_object(js_name = IpcClientSubscription)]
pub struct JsIpcClientSubscription {
    subscription: IpcClientSubscription,
}

#[bitwarden_ffi::wasm_export(js_class = IpcClientSubscription)]
impl JsIpcClientSubscription {
    #[wasm_only(
        note = "Use the `subscribe` method on `IpcClient` to create a subscription instance."
    )]
    #[allow(missing_docs)]
    pub async fn receive(
        &mut self,
        abort_signal: Option<AbortSignal>,
    ) -> Result<IncomingMessage, ReceiveError> {
        let cancellation_token = abort_signal.map(|signal| signal.to_cancellation_token());
        self.subscription.receive(cancellation_token).await
    }
}

#[bitwarden_ffi::wasm_export(js_class = IpcClient)]
impl JsIpcClient {
    /// Create a new `IpcClient` instance with an in-memory session repository for saving
    /// sessions within the SDK.
    #[wasm_only]
    #[wasm_bindgen(js_name = newWithSdkInMemorySessions)]
    pub fn new_with_sdk_in_memory_sessions(
        communication_provider: &JsCommunicationBackend,
    ) -> JsIpcClient {
        JsIpcClient {
            client: Arc::new(IpcClientImpl::new(
                NoiseCryptoProvider::new(),
                communication_provider.clone(),
                GenericSessionRepository::InMemory(Arc::new(InMemorySessionRepository::new(
                    HashMap::new(),
                ))),
            )),
        }
    }

    /// Create a new `IpcClient` instance with a client-managed session repository for saving
    /// sessions using State Provider.
    #[wasm_only]
    #[wasm_bindgen(js_name = newWithClientManagedSessions)]
    pub fn new_with_client_managed_sessions(
        communication_provider: &JsCommunicationBackend,
        session_repository: RawJsSessionRepository,
    ) -> JsIpcClient {
        JsIpcClient {
            client: Arc::new(IpcClientImpl::new(
                NoiseCryptoProvider::new(),
                communication_provider.clone(),
                GenericSessionRepository::JsSessionRepository(Arc::new(JsSessionRepository::new(
                    session_repository,
                ))),
            )),
        }
    }

    #[wasm_only]
    #[allow(missing_docs)]
    pub async fn start(
        &self,
        abort_signal: Option<AbortSignal>,
    ) -> Result<(), AlreadyRunningError> {
        self.client
            .start(abort_signal.map(|signal| signal.to_cancellation_token()))
            .await
    }

    #[wasm_only]
    #[wasm_bindgen(js_name = isRunning)]
    #[allow(missing_docs)]
    pub fn is_running(&self) -> bool {
        self.client.is_running()
    }

    #[wasm_only]
    #[allow(missing_docs)]
    pub async fn send(&self, message: OutgoingMessage) -> Result<(), JsError> {
        self.client
            .send(message)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_only]
    #[allow(missing_docs)]
    pub async fn broadcast(
        &self,
        group: BroadcastGroup,
        payload: Vec<u8>,
        topic: Option<String>,
    ) -> Result<Vec<IpcEndpointSendResult>, BroadcastError> {
        let results = self.client.broadcast(group, payload, topic).await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    #[wasm_only]
    #[allow(missing_docs)]
    pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> {
        let subscription = self.client.subscribe(None).await?;
        Ok(JsIpcClientSubscription { subscription })
    }
}
