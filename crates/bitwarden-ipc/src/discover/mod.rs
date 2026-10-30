#![doc = include_str!("README.md")]

use std::time::Duration;

use bitwarden_threading::{
    cancellation_token::CancellationToken,
    time::{sleep, timeout},
};
use serde::{Deserialize, Serialize};
use tokio::select;

use crate::{
    IpcClient, IpcClientExt, RequestError, RpcHandler, RpcRequestInfo, TypedReceiveError,
    endpoint::Endpoint, rpc::request::RpcRequest,
};

/// Upper bound for a single discover attempt in [`wait_for_peer`], so a lost message cannot stall
/// the wait. Must stay longer than the Noise handshake timeout (2s), so a handshake finishes or
/// fails on its own first.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause between failed discover attempts in [`wait_for_peer`].
const RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A request to discover/ping a client.
pub struct DiscoverRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
/// The response to a discover/ping request.
pub struct DiscoverResponse {
    /// The version of the client that responded to the discover request.
    pub version: String,
}

impl RpcRequest for DiscoverRequest {
    type Response = DiscoverResponse;

    const NAME: &str = "DiscoverRequest";
}

/// A simple handler for the `DiscoverRequest` that always returns the same response.
/// Used to enable discovery/ping functionality and provide version information.
pub struct DiscoverHandler {
    response: DiscoverResponse,
}

impl DiscoverHandler {
    /// Creates a new `DiscoverHandler` with the given response.
    pub fn new(response: DiscoverResponse) -> Self {
        Self { response }
    }
}

impl RpcHandler for DiscoverHandler {
    type Request = DiscoverRequest;

    async fn handle(&self, _request: Self::Request, _info: RpcRequestInfo) -> DiscoverResponse {
        self.response.clone()
    }
}

/// Waits until `destination` answers a [`DiscoverRequest`], retrying until it does or
/// `cancellation_token` is cancelled.
///
/// Use this before sending to a peer that may not have started yet. An error answer from the peer,
/// such as having no discover handler, is returned without retrying, since the peer is up.
pub async fn wait_for_peer<C: IpcClient + ?Sized>(
    client: &C,
    destination: Endpoint,
    cancellation_token: Option<CancellationToken>,
) -> Result<DiscoverResponse, RequestError> {
    let attempts = async {
        loop {
            let attempt = timeout(
                ATTEMPT_TIMEOUT,
                client.request(DiscoverRequest, destination.clone(), None),
            )
            .await;

            match attempt {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e @ RequestError::Rpc(_))) => return Err(e),
                _ => sleep(RETRY_DELAY).await,
            }
        }
    };

    let Some(cancellation_token) = cancellation_token else {
        return attempts.await;
    };
    select! {
        result = attempts => result,
        _ = cancellation_token.cancelled() => {
            Err(RequestError::Receive(TypedReceiveError::Cancelled))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use super::*;
    use crate::{
        HostId, IncomingMessage, IpcClientImpl, NoEncryptionCryptoProvider, Source,
        rpc::error::RpcError,
        traits::{InMemorySessionRepository, TestCommunicationBackend},
    };

    async fn start_client(backend: &TestCommunicationBackend) -> Arc<dyn IpcClient> {
        let client: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
            NoEncryptionCryptoProvider,
            backend.clone(),
            InMemorySessionRepository::new(HashMap::new()),
        ));
        client.start(None).await.expect("client starts");
        client
    }

    fn peer() -> Endpoint {
        Endpoint::BrowserBackground { id: HostId::Own }
    }

    /// Deliver the messages sent through `from` to `to`, as if they came from `source`.
    async fn relay(from: &TestCommunicationBackend, to: &TestCommunicationBackend, source: Source) {
        for message in from.drain_outgoing().await {
            to.push_incoming(IncomingMessage {
                payload: message.payload,
                destination: message.destination,
                source: source.clone(),
                topic: message.topic,
            });
        }
    }

    /// Relay one discover round trip between the waiting client and the peer.
    async fn round_trip(client: &TestCommunicationBackend, peer: &TestCommunicationBackend) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        relay(client, peer, Source::BrowserForeground { id: 1 }).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        relay(peer, client, Source::BrowserBackground { id: HostId::Own }).await;
    }

    async fn start_peer(with_handler: bool) -> TestCommunicationBackend {
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;
        if with_handler {
            client
                .register_rpc_handler(DiscoverHandler::new(DiscoverResponse {
                    version: "1.0.0".to_string(),
                }))
                .await;
        }
        backend
    }

    #[tokio::test(start_paused = true)]
    async fn test_wait_for_peer_retries_until_the_peer_answers() {
        let peer_backend = start_peer(true).await;
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;

        let wait = tokio::spawn(async move { wait_for_peer(client.as_ref(), peer(), None).await });

        // The first attempt is lost, as if the peer had not started.
        tokio::time::sleep(Duration::from_millis(20)).await;
        backend.drain_outgoing().await;
        tokio::time::sleep(ATTEMPT_TIMEOUT + RETRY_DELAY).await;
        round_trip(&backend, &peer_backend).await;

        let response = wait.await.expect("task joins").expect("peer answers");
        assert_eq!(response.version, "1.0.0");
    }

    #[tokio::test(start_paused = true)]
    async fn test_wait_for_peer_returns_peer_errors_without_retrying() {
        let peer_backend = start_peer(false).await;
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;

        let wait = tokio::spawn(async move { wait_for_peer(client.as_ref(), peer(), None).await });
        round_trip(&backend, &peer_backend).await;

        let result = wait.await.expect("task joins");
        assert!(matches!(
            result,
            Err(RequestError::Rpc(RpcError::NoHandlerFound))
        ));
        assert!(backend.drain_outgoing().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_wait_for_peer_stops_when_cancelled() {
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;
        let cancellation_token = CancellationToken::new();

        let wait = tokio::spawn({
            let cancellation_token = cancellation_token.clone();
            async move { wait_for_peer(client.as_ref(), peer(), Some(cancellation_token)).await }
        });
        tokio::time::sleep(ATTEMPT_TIMEOUT * 2).await;
        cancellation_token.cancel();

        let result = wait.await.expect("task joins");
        assert!(matches!(
            result,
            Err(RequestError::Receive(TypedReceiveError::Cancelled))
        ));
    }
}
