use std::{collections::HashMap, sync::Arc};

use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
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
    reachability::{ReachabilityHandle, ReachabilityTracker},
    traits::InMemorySessionRepository,
    wasm::{
        JsSessionRepository, RawJsSessionRepository,
        generic_session_repository::GenericSessionRepository,
    },
};

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
    ) -> JsIpcClient {
        JsIpcClient {
            client: Arc::new(IpcClientImpl::new(
                NoiseCryptoProvider,
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
                NoiseCryptoProvider,
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
    pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> {
        let subscription = self.client.subscribe(None).await?;
        Ok(JsIpcClientSubscription { subscription })
    }

    /// The reachability tracker for this client. Use it to track a peer endpoint and query whether
    /// it is reachable.
    #[wasm_only]
    pub fn reachability(&self) -> JsReachabilityTracker {
        JsReachabilityTracker {
            tracker: self.client.reachability(),
        }
    }
}

/// JavaScript wrapper around the reachability tracker. See
/// [`ReachabilityTracker`](crate::ReachabilityTracker).
#[wasm_bindgen(js_name = ReachabilityTracker)]
pub struct JsReachabilityTracker {
    tracker: Arc<ReachabilityTracker>,
}

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = ReachabilityTracker)]
impl JsReachabilityTracker {
    /// Begin tracking `endpoint`'s reachability, returning a handle. Hold the handle for as long as
    /// you care about the endpoint; calling `free()` on it (or letting it be garbage-collected)
    /// stops tracking that endpoint.
    #[wasm_only]
    pub fn track(&self, endpoint: Endpoint) -> JsReachabilityHandle {
        JsReachabilityHandle {
            handle: self.tracker.track(endpoint),
        }
    }
}

/// JavaScript wrapper around a reachability handle. See
/// [`ReachabilityHandle`](crate::ReachabilityHandle).
#[wasm_bindgen(js_name = ReachabilityHandle)]
pub struct JsReachabilityHandle {
    handle: ReachabilityHandle,
}

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = ReachabilityHandle)]
impl JsReachabilityHandle {
    /// Whether the tracked endpoint is currently reachable.
    #[wasm_only]
    #[wasm_bindgen(js_name = isReachable)]
    pub async fn is_reachable(&self) -> bool {
        self.handle.is_reachable().await
    }
}
