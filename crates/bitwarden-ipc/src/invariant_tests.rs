//! Invariant test suite for the IPC framework.
//!
//! Each test encodes one property the framework is meant to guarantee. A passing test means the
//! invariant currently holds; an `#[ignore]`d test documents an invariant that is currently
//! violated, and its `ignore` reason explains the gap and where it lives. Run the documented gaps
//! with `cargo test -p bitwarden-ipc --lib -- --ignored`.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    Endpoint, HostId, IncomingMessage, IpcClient, IpcClientExt, IpcClientImpl,
    NoEncryptionCryptoProvider, NoiseCryptoProvider, NoiseCryptoProviderState, OutgoingMessage,
    RpcRequest, SendError, Source,
    rpc::{request_message::RpcRequestMessage, response_message::IncomingRpcResponseMessage},
    serde_utils,
    traits::{InMemorySessionRepository, SessionRepository, TestCommunicationBackend},
};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct SumRequest {
    a: i32,
    b: i32,
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct SumResponse {
    result: i32,
}
impl RpcRequest for SumRequest {
    type Response = SumResponse;
    const NAME: &str = "SumRequest";
}

/// INVARIANT (delivery + correlation): with many requests of the *same type* in flight at
/// once, each receives exactly its own response. Strengthens the two-request case already covered
/// in `ipc_client::tests`.
#[tokio::test]
async fn many_concurrent_same_type_requests_each_receive_their_own_response() {
    const N: i32 = 6;
    let comm = TestCommunicationBackend::new();
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        comm.clone(),
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client.start(None).await;

    let mut handles = Vec::new();
    for i in 0..N {
        let client = client.clone();
        handles.push((
            i,
            tokio::spawn(async move {
                client
                    .request::<SumRequest>(
                        SumRequest { a: i, b: 100 },
                        Endpoint::BrowserBackground { id: HostId::Own },
                        None,
                    )
                    .await
            }),
        ));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let outgoing = comm.outgoing().await;
    assert_eq!(
        outgoing.len(),
        N as usize,
        "expected one outgoing message per request"
    );
    for message in outgoing {
        let request: RpcRequestMessage<SumRequest> =
            serde_utils::from_slice(&message.payload).expect("request should deserialize");
        let response = IncomingRpcResponseMessage {
            result: Ok(SumResponse {
                result: request.request.a + request.request.b,
            }),
            request_id: request.request_id.clone(),
            request_type: request.request_type.clone(),
        };
        comm.push_incoming(IncomingMessage {
            payload: serde_utils::to_vec(&response).expect("response should serialize"),
            source: Source::BrowserBackground { id: HostId::Own },
            destination: Endpoint::Web {
                tab_id: 1,
                document_id: "doc".to_string(),
            },
            topic: Some(request.response_topic.clone()),
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    for (i, handle) in handles {
        let result = handle
            .await
            .expect("task panicked")
            .expect("request should succeed");
        assert_eq!(
            result.result,
            i + 100,
            "request a={i} received the wrong response"
        );
    }
}

struct FailingSessionRepository;
impl SessionRepository<NoiseCryptoProviderState> for FailingSessionRepository {
    type GetError = String;
    type SaveError = String;
    type RemoveError = String;
    async fn get(&self, _dst: Endpoint) -> Result<Option<NoiseCryptoProviderState>, String> {
        Err("session store unavailable".to_string())
    }
    async fn save(&self, _dst: Endpoint, _s: NoiseCryptoProviderState) -> Result<(), String> {
        Err("session store unavailable".to_string())
    }
    async fn remove(&self, _dst: Endpoint) -> Result<(), String> {
        Err("session store unavailable".to_string())
    }
}

/// INVARIANT (robustness): a failure in the session store surfaces as a `SendError`, not a
/// panic. The `CryptoProvider` trait docs promise exactly this.
#[tokio::test]
#[ignore = "INVARIANT VIOLATED: NoiseCryptoProvider calls .expect() on every SessionRepository op \
            (crypto_provider.rs:163,212,225,253,278,295,311,362,393,410). A failing client-managed \
            session store panics; in WASM that aborts the whole module instead of returning a \
            SendError. Latent today because production uses in-memory sessions \
            (newWithSdkInMemorySessions), which never fail. Un-ignore when session errors are \
            propagated instead of unwrapped."]
async fn session_store_failure_surfaces_error_instead_of_crashing() {
    let client = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        TestCommunicationBackend::new(),
        FailingSessionRepository,
    );
    let _ = client.start(None).await;

    let result = client
        .send(OutgoingMessage {
            payload: vec![1, 2, 3],
            destination: Endpoint::DesktopMain,
            topic: None,
        })
        .await;

    assert!(
        matches!(
            result,
            Err(SendError::Other(_)) | Err(SendError::Unreachable)
        ),
        "expected a SendError, got {result:?}"
    );
}

/// INVARIANT (concurrency): a send that stalls (a handshake to an unreachable peer) must not
/// block sends to *other* peers. Hub backends (browser-background, desktop-main) share one client
/// across many peers, so head-of-line blocking here stalls unrelated traffic.
#[tokio::test]
#[ignore = "INVARIANT VIOLATED: NoiseCryptoProvider::send holds a single per-client mutex \
            (crypto_state_guard, crypto_provider.rs:205) across the whole send, including a \
            handshake that blocks up to HANDSHAKE_TIMEOUT_SECS (2s). Two sends to different peers \
            are fully serialized, so this test takes ~4s instead of ~2s. Un-ignore when send \
            concurrency is per-destination."]
async fn independent_sends_are_not_serialized_behind_a_slow_handshake() {
    // The test backend never delivers a handshake response, so every send's handshake runs to its
    // full 2s timeout. Concurrent sends would finish in ~2s; serialized ones in ~4s.
    let client = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        TestCommunicationBackend::new(),
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client.start(None).await;

    let started = Instant::now();
    let a = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .send(OutgoingMessage {
                    payload: vec![1],
                    destination: Endpoint::DesktopMain,
                    topic: None,
                })
                .await
        })
    };
    let b = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .send(OutgoingMessage {
                    payload: vec![2],
                    destination: Endpoint::BrowserBackground { id: HostId::Own },
                    topic: None,
                })
                .await
        })
    };
    let _ = tokio::join!(a, b);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "independent sends were serialized behind crypto_state_guard: took {elapsed:?} \
         (expected ~2s if concurrent, ~4s if serialized behind two 2s handshakes)"
    );
}

/// INVARIANT (concurrency + crypto): concurrent encrypted sends to the same peer are all
/// delivered and decryptable; crypto_state_guard prevents nonce reuse under concurrency.
#[tokio::test]
async fn concurrent_encrypted_sends_all_decrypt_without_nonce_reuse() {
    const K: u8 = 10;
    let (backend_1, backend_2) = crate::traits::TestTwoWayCommunicationBackend::new();

    let client_1 = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        backend_1,
        InMemorySessionRepository::new(HashMap::new()),
    );
    let client_2 = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        backend_2,
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client_1.start(None).await;
    let _ = client_2.start(None).await;

    let mut subscription = client_2
        .subscribe(None)
        .await
        .expect("subscribe should succeed");

    let mut handles = Vec::new();
    for i in 0..K {
        let client_1 = client_1.clone();
        handles.push(tokio::spawn(async move {
            client_1
                .send(OutgoingMessage {
                    payload: vec![i],
                    destination: Endpoint::DesktopMain,
                    topic: None,
                })
                .await
        }));
    }
    for handle in handles {
        let _ = handle.await.expect("send task panicked");
    }

    let mut seen = HashSet::new();
    for _ in 0..K {
        let message = tokio::time::timeout(Duration::from_secs(5), subscription.receive(None))
            .await
            .expect("timed out waiting for message")
            .expect("receive should succeed");
        seen.insert(message.payload[0]);
    }
    assert_eq!(
        seen.len(),
        K as usize,
        "expected {K} distinct decrypted payloads, saw {seen:?}"
    );
}

/// CONTRACT: the framework does not filter incoming messages by destination. It delivers every
/// received message to matching-topic subscribers and relies on the communication backend to only
/// hand it messages addressed to this endpoint (as the production transports do). This pins the
/// contract so that adding or removing framework-level destination filtering is a conscious change.
#[tokio::test]
async fn framework_does_not_filter_incoming_by_destination() {
    let comm = TestCommunicationBackend::new();
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        comm.clone(),
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client.start(None).await;
    let mut subscription = client
        .subscribe(None)
        .await
        .expect("subscribe should succeed");

    // Addressed to a different endpoint than any identity this client might have.
    let message = IncomingMessage {
        payload: vec![7],
        source: Source::DesktopMain,
        destination: Endpoint::DesktopRenderer,
        topic: None,
    };
    comm.push_incoming(message.clone());

    let received = tokio::time::timeout(Duration::from_secs(1), subscription.receive(None))
        .await
        .expect("receive should not hang")
        .expect("receive should succeed");
    assert_eq!(
        received, message,
        "framework delivered the message regardless of destination"
    );
}

/// CONTRACT: a subscription only receives messages published *after* it is created; messages
/// that arrived before `subscribe()` are not replayed (documented on `IpcClientSubscription`).
#[tokio::test]
async fn subscription_does_not_replay_messages_published_before_it_existed() {
    let comm = TestCommunicationBackend::new();
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        comm.clone(),
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client.start(None).await;

    let before = IncomingMessage {
        payload: vec![1],
        source: Source::DesktopMain,
        destination: Endpoint::DesktopMain,
        topic: None,
    };
    comm.push_incoming(before);
    // Let the processing loop consume the pre-subscription message.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut subscription = client
        .subscribe(None)
        .await
        .expect("subscribe should succeed");
    let after = IncomingMessage {
        payload: vec![2],
        source: Source::DesktopMain,
        destination: Endpoint::DesktopMain,
        topic: None,
    };
    comm.push_incoming(after.clone());

    let received = tokio::time::timeout(Duration::from_secs(1), subscription.receive(None))
        .await
        .expect("receive should not hang")
        .expect("receive should succeed");
    assert_eq!(
        received, after,
        "only the post-subscription message should be delivered"
    );
}

/// CONTRACT: a request whose cancellation token fires returns promptly with an error instead
/// of hanging forever, even when no response ever arrives.
#[tokio::test]
async fn request_returns_when_its_cancellation_token_fires() {
    use bitwarden_threading::cancellation_token::CancellationToken;

    let comm = TestCommunicationBackend::new();
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        comm,
        InMemorySessionRepository::new(HashMap::new()),
    );
    let _ = client.start(None).await;

    let token = CancellationToken::new();
    let token_clone = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        token_clone.cancel();
    });

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        client.request::<SumRequest>(
            SumRequest { a: 1, b: 2 },
            Endpoint::DesktopRenderer,
            Some(token),
        ),
    )
    .await;

    let inner = result.expect("request must return after cancellation, not hang");
    assert!(
        inner.is_err(),
        "cancelled request should resolve to an error, got {inner:?}"
    );
}
