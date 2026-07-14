//! Tests for the shared unlock system. These live in a separate file since many of these are beyond
//! unit-test scope, but still don't test public APIs.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_encoding::B64;
use bitwarden_ipc::{
    Endpoint, HostId, InMemorySessionRepository, IncomingMessage, IpcClient,
    NoEncryptionCryptoProvider, Source, TestCommunicationBackend, TestIpcClient,
    TypedIncomingMessage,
};

use crate::{
    DeviceEvent, Follower, FollowerMessage, Leader, LeaderMessage, LockState,
    drivers::SharedUnlockDriver,
};

#[derive(Clone)]
struct MockDriver {
    states: Arc<Mutex<HashMap<UserId, LockState>>>,
    vault_urls: Arc<Mutex<HashMap<UserId, String>>>,
    timeout_suppressions: Arc<Mutex<Vec<(UserId, Duration)>>>,
    endpoint: Endpoint,
}

impl MockDriver {
    fn new(initial: HashMap<UserId, LockState>) -> Self {
        Self {
            states: Arc::new(Mutex::new(initial)),
            vault_urls: Arc::new(Mutex::new(HashMap::new())),
            timeout_suppressions: Arc::new(Mutex::new(Vec::new())),
            endpoint: Endpoint::DesktopMain,
        }
    }

    fn with_vault_urls(
        initial: HashMap<UserId, LockState>,
        vault_urls: HashMap<UserId, String>,
    ) -> Self {
        Self {
            states: Arc::new(Mutex::new(initial)),
            vault_urls: Arc::new(Mutex::new(vault_urls)),
            timeout_suppressions: Arc::new(Mutex::new(Vec::new())),
            endpoint: Endpoint::DesktopMain,
        }
    }

    fn get_state(&self, user_id: UserId) -> LockState {
        self.states
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .unwrap_or(LockState::Locked)
    }
}

#[async_trait::async_trait]
impl SharedUnlockDriver for MockDriver {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.states
            .lock()
            .unwrap()
            .insert(user_id, LockState::Locked);
        Ok(())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: SymmetricCryptoKey) -> Result<(), ()> {
        self.states
            .lock()
            .unwrap()
            .insert(user_id, LockState::Unlocked { user_key });
        Ok(())
    }

    async fn list_users(&self) -> Vec<UserId> {
        self.states.lock().unwrap().keys().copied().collect()
    }

    async fn get_user_lock_state(&self, user_id: UserId) -> LockState {
        self.get_state(user_id)
    }

    async fn get_vault_url(&self, user_id: UserId) -> Option<String> {
        self.vault_urls.lock().unwrap().get(&user_id).cloned()
    }

    async fn suppress_vault_timeout(&self, user_id: UserId, suppression_duration: Duration) {
        self.timeout_suppressions
            .lock()
            .unwrap()
            .push((user_id, suppression_duration));
    }
    async fn discover_leader(&self) -> Option<Endpoint> {
        Some(self.endpoint.clone())
    }
}

const LEADER_ENDPOINT: Endpoint = Endpoint::DesktopMain;

fn follower_source() -> Source {
    Source::BrowserBackground { id: HostId::Own }
}

fn test_user_key() -> SymmetricCryptoKey {
    SymmetricCryptoKey::try_from(B64::from([1u8; 64].to_vec())).unwrap()
}

fn user_a() -> UserId {
    "00000000-0000-0000-0000-000000000001".parse().unwrap()
}

fn user_b() -> UserId {
    "00000000-0000-0000-0000-000000000002".parse().unwrap()
}

struct Harness {
    leader: Leader<MockDriver>,
    follower: Follower<MockDriver>,
    leader_lock: MockDriver,
    follower_lock: MockDriver,
    leader_ipc_backend: TestCommunicationBackend,
    follower_ipc_backend: TestCommunicationBackend,
}

impl Harness {
    async fn new(
        leader_states: HashMap<UserId, LockState>,
        follower_states: HashMap<UserId, LockState>,
    ) -> Self {
        Self::new_with_vault_urls(leader_states, follower_states, HashMap::new()).await
    }

    async fn new_with_vault_urls(
        leader_states: HashMap<UserId, LockState>,
        follower_states: HashMap<UserId, LockState>,
        vault_urls: HashMap<UserId, String>,
    ) -> Self {
        let leader_lock = MockDriver::with_vault_urls(leader_states, vault_urls);
        let leader_ipc_backend = TestCommunicationBackend::new();
        let leader_ipc_client: Arc<dyn IpcClient> = Arc::new(TestIpcClient::new(
            NoEncryptionCryptoProvider,
            leader_ipc_backend.clone(),
            InMemorySessionRepository::new(HashMap::new()),
        ));
        let leader = Leader::create(leader_lock.clone(), leader_ipc_client);

        let follower_lock = MockDriver::new(follower_states);
        let follower_ipc_backend = TestCommunicationBackend::new();
        let ipc_client: Arc<dyn IpcClient> = Arc::new(TestIpcClient::new(
            NoEncryptionCryptoProvider,
            follower_ipc_backend.clone(),
            InMemorySessionRepository::new(HashMap::new()),
        ));

        let follower = Follower::create(follower_lock.clone(), ipc_client);
        follower.start_sessions().await;

        let mut harness = Self {
            leader,
            follower,
            leader_lock,
            follower_lock,
            leader_ipc_backend,
            follower_ipc_backend,
        };

        // Pump startup messages (StartSession -> LockStateUpdate responses)
        harness.pump().await;
        harness
    }

    /// Deliver all messages from follower IPC backend to leader
    async fn deliver_follower_to_leader(&mut self) -> usize {
        self.deliver_follower_to_leader_as(follower_source()).await
    }

    /// Deliver all messages from follower IPC backend to leader with a specific source
    async fn deliver_follower_to_leader_as(&mut self, source: Source) -> usize {
        let outgoing = self.follower_ipc_backend.drain_outgoing().await;
        let count = outgoing.len();
        for outgoing_msg in outgoing {
            let incoming = IncomingMessage {
                payload: outgoing_msg.payload,
                destination: outgoing_msg.destination,
                source: source.clone(),
                topic: outgoing_msg.topic,
            };
            let typed: TypedIncomingMessage<FollowerMessage> = incoming
                .try_into()
                .expect("Failed to decode follower message from IPC");
            self.leader.receive_message(typed).await.unwrap();
        }
        count
    }

    /// Deliver all messages from leader IPC backend to follower
    async fn deliver_leader_to_follower(&mut self) -> usize {
        let outgoing = self.leader_ipc_backend.drain_outgoing().await;
        let count = outgoing.len();
        for outgoing_msg in outgoing {
            let incoming = IncomingMessage {
                payload: outgoing_msg.payload,
                destination: outgoing_msg.destination,
                source: Source::DesktopMain,
                topic: outgoing_msg.topic,
            };
            let typed: TypedIncomingMessage<LeaderMessage> = incoming
                .try_into()
                .expect("Failed to decode leader message from IPC");
            self.follower.receive_message(typed).await.unwrap();
        }
        count
    }

    /// Pump messages in both directions until quiescent
    async fn pump(&mut self) {
        loop {
            let f2l = self.deliver_follower_to_leader().await;
            let l2f = self.deliver_leader_to_follower().await;
            if f2l == 0 && l2f == 0 {
                break;
            }
        }
    }
}

// --- Tests ---

#[tokio::test]
async fn test_follower_startup_locked() {
    let user = user_a();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);

    let harness = Harness::new(leader_states, follower_states).await;

    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
    assert_eq!(harness.follower_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_follower_startup_unlocked_propagates_to_leader() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(
        user,
        LockState::Unlocked {
            user_key: key.clone(),
        },
    )]);

    let harness = Harness::new(leader_states, follower_states).await;

    // Leader should have been unlocked by the follower's StartSession
    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked {
            user_key: key.clone()
        }
    );
    // Follower should remain unlocked
    assert_eq!(
        harness.follower_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}

#[tokio::test]
async fn test_follower_lock_propagates_to_leader() {
    let user = user_a();
    let key = test_user_key();
    // Both start unlocked
    let unlocked = LockState::Unlocked {
        user_key: key.clone(),
    };
    let leader_states = HashMap::from([(user, unlocked.clone())]);
    let follower_states = HashMap::from([(user, unlocked)]);

    let mut harness = Harness::new(leader_states, follower_states).await;

    // Follower manually locks
    harness
        .follower
        .handle_device_event(DeviceEvent::ManualLock { user_id: user })
        .await
        .unwrap();

    harness.pump().await;

    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_leader_lock_broadcasts_to_follower() {
    let user = user_a();
    let key = test_user_key();
    let unlocked = LockState::Unlocked {
        user_key: key.clone(),
    };
    let leader_states = HashMap::from([(user, unlocked.clone())]);
    let follower_states = HashMap::from([(user, unlocked)]);

    let mut harness = Harness::new(leader_states, follower_states).await;

    // Leader manually locks via device event
    harness
        .leader
        .handle_device_event(DeviceEvent::ManualLock { user_id: user })
        .await
        .unwrap();

    harness.pump().await;

    assert_eq!(harness.follower_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_leader_unlock_broadcasts_to_follower() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);

    let mut harness = Harness::new(leader_states, follower_states).await;

    // Leader manually unlocks via device event
    harness
        .leader
        .handle_device_event(DeviceEvent::ManualUnlock {
            user_id: user,
            user_key: key.clone(),
        })
        .await
        .unwrap();

    harness.pump().await;

    assert_eq!(
        harness.follower_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}

#[tokio::test]
async fn test_multiple_users_startup() {
    let a = user_a();
    let b = user_b();
    let key = test_user_key();

    let leader_states = HashMap::from([(a, LockState::Locked), (b, LockState::Locked)]);
    let follower_states = HashMap::from([
        (a, LockState::Locked),
        (
            b,
            LockState::Unlocked {
                user_key: key.clone(),
            },
        ),
    ]);

    let harness = Harness::new(leader_states, follower_states).await;

    // User A: both locked
    assert_eq!(harness.leader_lock.get_state(a), LockState::Locked);
    assert_eq!(harness.follower_lock.get_state(a), LockState::Locked);

    // User B: follower was unlocked, so leader should also be unlocked
    assert_eq!(
        harness.leader_lock.get_state(b),
        LockState::Unlocked {
            user_key: key.clone()
        }
    );
    assert_eq!(
        harness.follower_lock.get_state(b),
        LockState::Unlocked { user_key: key }
    );
}

#[tokio::test]
async fn test_web_source_with_matching_origin_is_accepted() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(
        user,
        LockState::Unlocked {
            user_key: key.clone(),
        },
    )]);
    let vault_urls = HashMap::from([(user, "https://vault.bitwarden.com".to_string())]);

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://vault.bitwarden.com".to_string(),
    };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            destination: LEADER_ENDPOINT,
            source: web_source,
        })
        .await
        .unwrap();

    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}

#[tokio::test]
async fn test_web_source_with_mismatched_origin_is_rejected() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    let vault_urls = HashMap::from([(user, "https://vault.bitwarden.com".to_string())]);

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://evil.example.com".to_string(),
    };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            destination: LEADER_ENDPOINT,
            source: web_source,
        })
        .await
        .unwrap();

    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_web_source_without_configured_vault_url_is_rejected() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    let vault_urls = HashMap::new();

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://anything.example.com".to_string(),
    };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            destination: LEADER_ENDPOINT,
            source: web_source,
        })
        .await
        .unwrap();

    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_web_source_lock_state_update_with_mismatched_origin_is_rejected() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    let vault_urls = HashMap::from([(user, "https://vault.bitwarden.com".to_string())]);

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://evil.example.com".to_string(),
    };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::LockStateUpdate {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            destination: LEADER_ENDPOINT,
            source: web_source,
        })
        .await
        .unwrap();

    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_web_source_lock_state_update_with_matching_origin_is_accepted() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    let vault_urls = HashMap::from([(user, "https://vault.bitwarden.com".to_string())]);

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://vault.bitwarden.com".to_string(),
    };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::LockStateUpdate {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            destination: LEADER_ENDPOINT,
            source: web_source,
        })
        .await
        .unwrap();

    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}

/// Tests that exercise the full encrypted (Noise) transport, including reconnection after the
/// leader has been offline. Unlike the manual-pump harness above (which uses
/// [`NoEncryptionCryptoProvider`] and hand-delivers already-decoded payloads), these tests run real
/// [`IpcClient`] receive loops over a controllable in-memory link so the Noise handshake and
/// session-cleanup-on-send-failure logic are actually driven.
mod reconnect {
    use std::sync::atomic::{AtomicBool, Ordering};

    use bitwarden_ipc::{
        CommunicationBackend, CommunicationBackendReceiver, Endpoint, ErrorKind, IpcClient,
        IpcClientImpl, IpcErrorKind, NoiseCryptoProvider, NoiseCryptoProviderState,
        OutgoingMessage,
    };
    use bitwarden_threading::{cancellation_token::CancellationToken, time::sleep};
    use tokio::sync::{Mutex, RwLock, broadcast};

    use super::*;

    /// Send error for [`Link`]. When the link is offline the destination is unreachable, which the
    /// Noise provider treats as a benign, non-fatal condition.
    #[derive(Debug)]
    enum LinkError {
        Unreachable,
    }

    impl IpcErrorKind for LinkError {
        fn kind(&self) -> ErrorKind {
            match self {
                LinkError::Unreachable => ErrorKind::Unreachable,
            }
        }
    }

    /// One end of a bidirectional in-memory transport between two peers. `send` pushes onto the
    /// peer's incoming channel and `subscribe` reads from our own; a shared `online` flag lets a
    /// test simulate the peer going offline (sends then fail as unreachable).
    #[derive(Clone)]
    struct Link {
        online: Arc<AtomicBool>,
        /// The peer's incoming channel: what our sends are delivered into.
        to_peer: broadcast::Sender<OutgoingMessage>,
        /// Our own incoming channel: receivers subscribe to this.
        from_peer: broadcast::Sender<OutgoingMessage>,
        /// Identity stamped onto messages we receive (i.e. the peer's source).
        peer_source: Source,
    }

    struct LinkReceiver {
        incoming: Mutex<broadcast::Receiver<OutgoingMessage>>,
        peer_source: Source,
    }

    impl Link {
        /// Create a connected pair of links plus the shared online flag that controls both.
        fn pair() -> (Link, Link, Arc<AtomicBool>) {
            let online = Arc::new(AtomicBool::new(true));
            let (follower_incoming, _) = broadcast::channel(256);
            let (leader_incoming, _) = broadcast::channel(256);

            let follower = Link {
                online: online.clone(),
                to_peer: leader_incoming.clone(),
                from_peer: follower_incoming.clone(),
                // The follower only ever talks to the leader (desktop).
                peer_source: Source::DesktopMain,
            };
            let leader = Link {
                online: online.clone(),
                to_peer: follower_incoming,
                from_peer: leader_incoming,
                peer_source: follower_source(),
            };
            (follower, leader, online)
        }
    }

    impl CommunicationBackend for Link {
        type SendError = LinkError;
        type Receiver = LinkReceiver;

        async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
            if !self.online.load(Ordering::SeqCst) {
                return Err(LinkError::Unreachable);
            }
            // A missing receiver just means the message is dropped, not that the peer is
            // unreachable, so the error is intentionally ignored.
            let _ = self.to_peer.send(message);
            Ok(())
        }

        async fn subscribe(&self) -> Self::Receiver {
            LinkReceiver {
                incoming: Mutex::new(self.from_peer.subscribe()),
                peer_source: self.peer_source.clone(),
            }
        }
    }

    impl CommunicationBackendReceiver for LinkReceiver {
        type ReceiveError = LinkError;

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            loop {
                let received = { self.incoming.lock().await.recv().await };
                match received {
                    Ok(message) => {
                        return Ok(IncomingMessage {
                            payload: message.payload,
                            destination: message.destination,
                            source: self.peer_source.clone(),
                            topic: message.topic,
                        });
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    // The channel is only closed when the harness is torn down; block forever
                    // rather than reporting a fatal error mid-test.
                    Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
                }
            }
        }
    }

    /// A session repository whose backing store can be inspected and cleared by the test, used to
    /// simulate a leader that restarted (and thus lost its Noise session) while offline.
    #[derive(Clone, Default)]
    struct SharedSessions(Arc<RwLock<HashMap<Endpoint, NoiseCryptoProviderState>>>);

    impl bitwarden_ipc::SessionRepository<NoiseCryptoProviderState> for SharedSessions {
        type GetError = ();
        type SaveError = ();
        type RemoveError = ();

        async fn get(
            &self,
            destination: Endpoint,
        ) -> Result<Option<NoiseCryptoProviderState>, Self::GetError> {
            Ok(self.0.read().await.get(&destination).cloned())
        }

        async fn save(
            &self,
            destination: Endpoint,
            session: NoiseCryptoProviderState,
        ) -> Result<(), Self::SaveError> {
            self.0.write().await.insert(destination, session);
            Ok(())
        }

        async fn remove(&self, destination: Endpoint) -> Result<(), Self::RemoveError> {
            self.0.write().await.remove(&destination);
            Ok(())
        }
    }

    /// Poll a driver's lock state until it matches `expected` or a generous timeout elapses.
    async fn wait_for_state(driver: &MockDriver, user: UserId, expected: &LockState) -> bool {
        for _ in 0..250 {
            if &driver.get_state(user) == expected {
                return true;
            }
            sleep(Duration::from_millis(20)).await;
        }
        &driver.get_state(user) == expected
    }

    /// A leader + follower connected over an encrypted link, each running real IPC receive loops.
    struct EncryptedHarness {
        follower: Follower<MockDriver>,
        leader_lock: MockDriver,
        leader_sessions: SharedSessions,
        online: Arc<AtomicBool>,
        // Retained for the harness's lifetime; the spawned IPC/leader tasks are torn down when the
        // test's tokio runtime shuts down at the end of the test.
        _token: CancellationToken,
    }

    impl EncryptedHarness {
        async fn new(
            leader_states: HashMap<UserId, LockState>,
            follower_driver: MockDriver,
        ) -> Self {
            let (follower_link, leader_link, online) = Link::pair();
            let token = CancellationToken::new();

            // Leader: an IPC client whose internal loop performs the Noise handshake, plus the
            // shared-unlock leader that reacts to decoded follower messages.
            let leader_lock = MockDriver::new(leader_states);
            let leader_sessions = SharedSessions::default();
            let leader_ipc: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
                NoiseCryptoProvider,
                leader_link,
                leader_sessions.clone(),
            ));
            leader_ipc
                .start(Some(token.clone()))
                .await
                .expect("Leader IPC client should start");
            let leader = Leader::create(leader_lock.clone(), leader_ipc);
            leader
                .start(Some(token.clone()))
                .await
                .expect("Leader should start");

            // Follower: only ever sends, so its IPC client does not need its own receive loop.
            let follower_ipc: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
                NoiseCryptoProvider,
                follower_link,
                bitwarden_ipc::InMemorySessionRepository::<NoiseCryptoProviderState>::new(
                    HashMap::new(),
                ),
            ));
            let follower = Follower::create(follower_driver, follower_ipc);

            Self {
                follower,
                leader_lock,
                leader_sessions,
                online,
                _token: token,
            }
        }

        fn set_online(&self, online: bool) {
            self.online.store(online, Ordering::SeqCst);
        }
    }

    /// Full reconnection cycle:
    /// 1. The follower shares its unlocked state; the leader unlocks.
    /// 2. The leader goes offline. The follower's next send fails, which clears the follower's
    ///    Noise session. The (restarted) leader loses its session too.
    /// 3. The leader comes back online. The follower's first send re-handshakes and successfully
    ///    re-shares the unlock without needing a second attempt.
    #[tokio::test]
    async fn test_reconnect_after_leader_offline_reshares_unlock() {
        let user = user_a();
        let key = test_user_key();

        // Leader starts locked; the follower is unlocked and will share its state.
        let follower_driver = MockDriver::new(HashMap::from([(
            user,
            LockState::Unlocked {
                user_key: key.clone(),
            },
        )]));
        let harness =
            EncryptedHarness::new(HashMap::from([(user, LockState::Locked)]), follower_driver)
                .await;

        // --- 1. Share unlock over a freshly established encrypted session ---
        harness.follower.start_sessions().await;
        assert!(
            wait_for_state(
                &harness.leader_lock,
                user,
                &LockState::Unlocked {
                    user_key: key.clone()
                }
            )
            .await,
            "Leader should unlock after the follower shares its unlocked state"
        );

        // --- 2. Leader goes offline; the follower's send fails and clears its crypto state ---
        harness.set_online(false);
        // Simulate the leader relocking and losing its Noise session (e.g. a restart) while down.
        harness
            .leader_lock
            .states
            .lock()
            .unwrap()
            .insert(user, LockState::Locked);
        harness.leader_sessions.0.write().await.clear();

        // This send cannot be delivered; the Noise provider discards the follower's session so the
        // next send is forced to re-handshake. The follower swallows the unreachable error.
        harness.follower.start_sessions().await;
        assert_eq!(
            harness.leader_lock.get_state(user),
            LockState::Locked,
            "Leader must stay locked while offline"
        );

        // --- 3. Leader is back; the first reconnect attempt re-handshakes and re-shares unlock ---
        harness.set_online(true);
        harness.follower.start_sessions().await;
        assert!(
            wait_for_state(
                &harness.leader_lock,
                user,
                &LockState::Unlocked {
                    user_key: key.clone()
                }
            )
            .await,
            "Leader should unlock again after the follower reconnects on the first attempt"
        );
    }
}

#[tokio::test]
async fn test_non_web_source_skips_origin_validation() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    let vault_urls = HashMap::from([(user, "https://vault.bitwarden.com".to_string())]);

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let browser_source = Source::BrowserBackground { id: HostId::Own };

    harness
        .leader
        .receive_message(TypedIncomingMessage {
            payload: FollowerMessage::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            destination: LEADER_ENDPOINT,
            source: browser_source,
        })
        .await
        .unwrap();

    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}
