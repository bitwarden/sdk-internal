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

/// Drains a leader IPC backend's outgoing queue and decodes the messages without delivering
/// them (used to inspect what a leader emitted).
async fn drain_leader_messages(backend: &TestCommunicationBackend) -> Vec<LeaderMessage> {
    backend
        .drain_outgoing()
        .await
        .into_iter()
        .map(|outgoing| {
            let incoming = IncomingMessage {
                payload: outgoing.payload,
                destination: outgoing.destination,
                source: Source::DesktopMain,
                topic: outgoing.topic,
            };
            TypedIncomingMessage::<LeaderMessage>::try_from(incoming)
                .expect("Failed to decode leader message")
                .payload
        })
        .collect()
}

/// A heartbeat from an unknown endpoint should make the leader ask for a session start once,
/// then record the endpoint so later heartbeats are answered with a `HeartBeat` echo. Without
/// that, a lost `StartSession` reply leaves the endpoint unknown and every heartbeat re-triggers
/// `RequestSessionStart`, churning indefinitely.
#[tokio::test]
async fn heartbeat_from_unknown_follower_does_not_churn_request_session_start() {
    let user = user_a();

    // A freshly reloaded leader: it knows the user is locked but has an empty session table.
    let leader_lock = MockDriver::new(HashMap::from([(user, LockState::Locked)]));
    let leader_ipc_backend = TestCommunicationBackend::new();
    let leader_ipc_client: Arc<dyn IpcClient> = Arc::new(TestIpcClient::new(
        NoEncryptionCryptoProvider,
        leader_ipc_backend.clone(),
        InMemorySessionRepository::new(HashMap::new()),
    ));
    let leader = Leader::create(leader_lock, leader_ipc_client);

    // Send several heartbeats from the same endpoint without ever delivering a StartSession
    // reply back to it. Desired behavior: at most the first heartbeat asks for a session start;
    // once the leader knows the endpoint, later heartbeats are answered with a HeartBeat echo,
    // not another RequestSessionStart.
    for iteration in 0..5 {
        leader
            .receive_message(TypedIncomingMessage {
                payload: FollowerMessage::HeartBeat { user_id: user },
                destination: LEADER_ENDPOINT,
                source: follower_source(),
            })
            .await
            .unwrap();

        let emitted = drain_leader_messages(&leader_ipc_backend).await;
        if iteration == 0 {
            // A single session-start request on first contact is acceptable.
            continue;
        }
        assert!(
            emitted
                .iter()
                .any(|m| matches!(m, LeaderMessage::HeartBeat { .. })),
            "after first contact the leader must recognize the endpoint and echo the heartbeat, \
             but it emitted {emitted:?}"
        );
        assert!(
            !emitted
                .iter()
                .any(|m| matches!(m, LeaderMessage::RequestSessionStart { .. })),
            "repeated heartbeats from a known endpoint must not keep re-triggering \
             RequestSessionStart (got {emitted:?})"
        );
    }
}
