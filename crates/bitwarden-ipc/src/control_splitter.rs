//! A [`CommunicationBackend`] decorator that keeps reachability control frames off the crypto
//! channel.
//!
//! Reachability ping/pong frames travel over the raw transport (so they can measure liveness
//! without a crypto session), but the crypto layer reads the same transport and would try to decode
//! them as Noise frames, aborting in-flight handshakes. This wrapper splits the inbound stream in
//! two: the receivers handed to the crypto layer ([`CommunicationBackend::subscribe`]) drop control
//! frames, while [`ControlSplitter::subscribe_control`] yields only the control messages. `send`
//! and `reachability` pass straight through, so the crypto provider stays entirely unaware of
//! reachability.

use std::sync::Arc;

use crate::{
    control::{ControlMessage, IncomingControlMessage, is_control_topic},
    endpoint::Endpoint,
    message::{IncomingMessage, OutgoingMessage},
    traits::{CommunicationBackend, CommunicationBackendReceiver, Reachability},
};

/// Wraps a communication backend so reachability control frames are separated from data frames. The
/// crypto layer only ever sees data; the reachability tracker consumes the control stream.
// Public (but hidden) only because it appears in `IpcClientImpl`'s public trait bounds: the client
// hands this wrapper to the crypto provider so control frames never reach it. It is not part of the
// supported API and should not be used directly.
#[doc(hidden)]
pub struct ControlSplitter<Com> {
    backend: Arc<Com>,
}

impl<Com: CommunicationBackend> ControlSplitter<Com> {
    pub(crate) fn new(backend: Arc<Com>) -> Self {
        Self { backend }
    }

    /// Subscribe to the inbound control-plane stream. Mirrors [`CommunicationBackendReceiver`]:
    /// call [`ControlReceiver::receive`] for the next control message. Data frames are filtered
    /// out (they reach the crypto layer via [`CommunicationBackend::subscribe`]).
    pub(crate) async fn subscribe_control(&self) -> ControlReceiver<Com::Receiver> {
        ControlReceiver {
            inner: self.backend.subscribe().await,
        }
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

/// Data-frame receiver handed to the crypto layer: drops control-topic frames so crypto never sees
/// them.
#[doc(hidden)]
pub struct ControlSplitterReceiver<R> {
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

/// Control-frame receiver: yields inbound [`ControlMessage`]s, skipping data frames.
pub(crate) struct ControlReceiver<R> {
    inner: R,
}

impl<R: CommunicationBackendReceiver> ControlReceiver<R> {
    /// Receive the next control message. Blocks asynchronously, skipping data frames, until a
    /// control frame arrives or the underlying receiver errors.
    pub(crate) async fn receive(&self) -> Result<IncomingControlMessage, R::ReceiveError> {
        loop {
            let message = self.inner.receive().await?;
            if let Some(control) = ControlMessage::from_topic(message.topic.as_deref()) {
                return Ok(IncomingControlMessage {
                    message: control,
                    source: message.source,
                });
            }
        }
    }
}
