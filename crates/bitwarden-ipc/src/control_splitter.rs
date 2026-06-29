//! A [`CommunicationBackend`] decorator that keeps reachability control frames off the crypto
//! channel.
//!
//! Reachability ping/pong frames travel over the raw transport (so they can measure liveness
//! without a crypto session), but the crypto layer reads the same transport and would try to decode
//! them as Noise frames, aborting in-flight handshakes. This wrapper peels reserved control-topic
//! frames off before any crypto-facing receiver yields them, and routes them to the
//! [`ReachabilityTracker`] from a single dedicated handler task. `send` and `reachability` pass
//! straight through to the inner backend, so the crypto provider stays entirely unaware of
//! reachability.

use std::sync::Arc;

use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::select;

use crate::{
    control::is_control_topic,
    endpoint::Endpoint,
    error::IpcErrorKind,
    message::{IncomingMessage, OutgoingMessage},
    reachability::ReachabilityTracker,
    traits::{CommunicationBackend, CommunicationBackendReceiver, Reachability},
};

/// Wraps a communication backend so reachability control frames bypass crypto. The receivers handed
/// to the crypto layer silently drop control frames; a single dedicated handler task routes them to
/// the tracker (recording liveness and answering pings).
pub(crate) struct ControlSplitter<Com> {
    backend: Arc<Com>,
    tracker: Arc<ReachabilityTracker>,
}

impl<Com: CommunicationBackend> ControlSplitter<Com> {
    pub(crate) fn new(backend: Arc<Com>, tracker: Arc<ReachabilityTracker>) -> Self {
        Self { backend, tracker }
    }

    /// Spawn the single task that consumes control frames from the raw transport and drives the
    /// tracker. Spawned once when the client starts, so there is exactly one auto-pong responder
    /// regardless of how many crypto receivers exist. The task stops when `cancellation_token` is
    /// cancelled (i.e. when the client stops), so it does not leak across a stop/restart.
    pub(crate) fn spawn_control_handler(&self, cancellation_token: CancellationToken) {
        let backend = self.backend.clone();
        let tracker = self.tracker.clone();
        let future = async move {
            let receiver = backend.subscribe().await;
            loop {
                select! {
                    _ = cancellation_token.cancelled() => break,
                    received = receiver.receive() => match received {
                        Ok(message) if is_control_topic(message.topic.as_deref()) => {
                            tracker.handle_inbound(message).await;
                        }
                        // Data frames are delivered to the crypto layer's own receivers; ignore them.
                        Ok(_) => {}
                        Err(error) if error.is_fatal() => break,
                        Err(_) => {}
                    },
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
    }
}

impl<Com: CommunicationBackend> CommunicationBackend for ControlSplitter<Com> {
    type SendError = Com::SendError;
    type Receiver = ControlSplitterReceiver<Com::Receiver>;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.backend.send(message).await
    }

    async fn subscribe(&self) -> Self::Receiver {
        ControlSplitterReceiver {
            inner: self.backend.subscribe().await,
        }
    }

    async fn reachability(&self, endpoint: &Endpoint) -> Reachability {
        self.backend.reachability(endpoint).await
    }
}

/// Receiver wrapper that drops control-topic frames so the crypto layer never sees them.
pub(crate) struct ControlSplitterReceiver<R> {
    inner: R,
}

impl<R: CommunicationBackendReceiver> CommunicationBackendReceiver for ControlSplitterReceiver<R> {
    type ReceiveError = R::ReceiveError;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        loop {
            let message = self.inner.receive().await?;
            if is_control_topic(message.topic.as_deref()) {
                continue;
            }
            return Ok(message);
        }
    }
}
