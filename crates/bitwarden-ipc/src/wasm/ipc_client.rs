use std::{collections::HashMap, sync::Arc};

use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::communication_backend::JsCommunicationBackend;
use crate::{
    IpcClientImpl,
    crypto_provider::noise::crypto_provider::NoiseCryptoProvider,
    endpoint::Endpoint,
    error::{AlreadyRunningError, ReceiveError, SubscribeError},
    ipc_client::IpcClientSubscription,
    ipc_client_trait::IpcClient,
    message::{IncomingMessage, OutgoingMessage},
    traits::InMemorySessionRepository,
    wasm::{
        JsSessionRepository, RawJsSessionRepository,
        generic_session_repository::GenericSessionRepository,
    },
};

/// Reachability configuration for an `IpcClient`.
#[derive(Tsify, Serialize, Deserialize)]
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityConfig {
    /// The leader endpoints this client follows. The SDK runs an adaptive reachability ping
    /// for each of the targets, to determine at runtime whether they are reachable continuously.
    pub ping_targets: Vec<Endpoint>,
}

/// JavaScript wrapper around the IPC client. For more information, see the
/// [`IpcClient`] trait documentation.
#[wasm_bindgen(js_name = IpcClient)]
pub struct JsIpcClient {
    #[wasm_bindgen(skip)]
    /// The underlying IPC client instance. Use this to create WASM-compatible functions
    /// that interact with the IPC client, e.g. to register RPC handlers, trigger RPC requests,
    /// send typed messages, etc. For examples see
    /// [wasm::ipc_register_discover_handler](crate::wasm::ipc_register_discover_handler).
    pub client: Arc<dyn IpcClient>,
}

/// JavaScript wrapper around the IPC client subscription. For more information, see the
/// [IpcClientSubscription](crate::IpcClientSubscription) documentation.
#[wasm_bindgen(js_name = IpcClientSubscription)]
pub struct JsIpcClientSubscription {
    subscription: IpcClientSubscription,
}

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = IpcClientSubscription)]
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

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = IpcClient)]
impl JsIpcClient {
    /// Create a new `IpcClient` instance with an in-memory session repository for saving
    /// sessions within the SDK.
    #[wasm_only]
    #[wasm_bindgen(js_name = newWithSdkInMemorySessions)]
    pub fn new_with_sdk_in_memory_sessions(
        communication_provider: &JsCommunicationBackend,
        reachability: ReachabilityConfig,
    ) -> JsIpcClient {
        JsIpcClient {
            client: Arc::new(IpcClientImpl::new_with_reachability(
                NoiseCryptoProvider,
                communication_provider.clone(),
                GenericSessionRepository::InMemory(Arc::new(InMemorySessionRepository::new(
                    HashMap::new(),
                ))),
                reachability.ping_targets,
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
        reachability: ReachabilityConfig,
    ) -> JsIpcClient {
        JsIpcClient {
            client: Arc::new(IpcClientImpl::new_with_reachability(
                NoiseCryptoProvider,
                communication_provider.clone(),
                GenericSessionRepository::JsSessionRepository(Arc::new(JsSessionRepository::new(
                    session_repository,
                ))),
                reachability.ping_targets,
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
    pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> {
        let subscription = self.client.subscribe(None).await?;
        Ok(JsIpcClientSubscription { subscription })
    }

    /// Whether `endpoint` is currently reachable, per the client's reachability tracker: an
    /// endpoint is reachable when inbound traffic was seen from it within the active window.
    #[wasm_only]
    #[wasm_bindgen(js_name = isReachable)]
    pub async fn is_reachable(&self, endpoint: Endpoint) -> bool {
        self.client.is_reachable(endpoint).await
    }

    /// Immediately mark `endpoint` as unreachable (e.g. on a known transport disconnect), without
    /// waiting for the active window to elapse.
    #[wasm_only]
    #[wasm_bindgen(js_name = invalidateReachability)]
    pub fn invalidate_reachability(&self, endpoint: Endpoint) {
        self.client.invalidate_reachability(endpoint);
    }
}
