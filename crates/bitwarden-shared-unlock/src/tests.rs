//! Tests for the shared unlock system. These live in a separate file since many of these are beyond unit-test
//! scope, but still don't test public APIs.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_core::UserId;
use bitwarden_ipc::{
    Endpoint, HostId, InMemorySessionRepository, IpcClient, NoEncryptionCryptoProvider, Source,
    TestCommunicationBackend, TestIpcClient,
};

use crate::{
    DeviceEvent, Follower, Leader, LockState, Message, UserKey,
    drivers::{LeaderDiscovery, UserLockManagement},
};

#[derive(Clone)]
struct MockLockSystem {
    states: Arc<Mutex<HashMap<UserId, LockState>>>,
    vault_urls: Arc<Mutex<HashMap<UserId, String>>>,
    timeout_suppressions: Arc<Mutex<Vec<(UserId, Duration)>>>,
}

impl MockLockSystem {
    fn new(initial: HashMap<UserId, LockState>) -> Self {
        Self {
            states: Arc::new(Mutex::new(initial)),
            vault_urls: Arc::new(Mutex::new(HashMap::new())),
            timeout_suppressions: Arc::new(Mutex::new(Vec::new())),
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

impl UserLockManagement for MockLockSystem {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.states
            .lock()
            .unwrap()
            .insert(user_id, LockState::Locked);
        Ok(())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: UserKey) -> Result<(), ()> {
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

    async fn suppress_vault_timeout(&self, user_id: UserId, until: Duration) {
        self.timeout_suppressions
            .lock()
            .unwrap()
            .push((user_id, until));
    }
}

struct MockLeaderDiscovery {
    endpoint: Endpoint,
}

impl LeaderDiscovery for MockLeaderDiscovery {
    async fn discover_leader(&self) -> Option<Endpoint> {
        Some(self.endpoint.clone())
    }
}

const LEADER_ENDPOINT: Endpoint = Endpoint::DesktopMain;

fn follower_source() -> Source {
    Source::BrowserBackground { id: HostId::Own }
}

fn test_user_key() -> UserKey {
    UserKey::from_bytes(vec![1u8; 64])
}

fn user_a() -> UserId {
    "00000000-0000-0000-0000-000000000001".parse().unwrap()
}

fn user_b() -> UserId {
    "00000000-0000-0000-0000-000000000002".parse().unwrap()
}

struct Harness {
    leader: Leader<MockLockSystem>,
    follower: Follower<MockLockSystem, MockLeaderDiscovery>,
    leader_lock: MockLockSystem,
    follower_lock: MockLockSystem,
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
        let leader_lock = MockLockSystem::with_vault_urls(leader_states, vault_urls);
        let leader_ipc_backend = TestCommunicationBackend::new();
        let leader_ipc_client: Arc<dyn IpcClient> = Arc::new(TestIpcClient::new(
            NoEncryptionCryptoProvider,
            leader_ipc_backend.clone(),
            InMemorySessionRepository::new(HashMap::new()),
        ));
        let leader = Leader::create(leader_lock.clone(), leader_ipc_client);

        let follower_lock = MockLockSystem::new(follower_states);
        let follower_ipc_backend = TestCommunicationBackend::new();
        let ipc_client: Arc<dyn IpcClient> = Arc::new(TestIpcClient::new(
            NoEncryptionCryptoProvider,
            follower_ipc_backend.clone(),
            InMemorySessionRepository::new(HashMap::new()),
        ));

        let follower = Follower::create(
            follower_lock.clone(),
            MockLeaderDiscovery {
                endpoint: LEADER_ENDPOINT,
            },
            ipc_client,
        )
        .await;

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
            let msg = Message::from_cbor(&outgoing_msg.payload)
                .expect("Failed to decode CBOR message from IPC");
            self.leader
                .receive_message(msg, source.clone())
                .await
                .unwrap();
        }
        count
    }

    /// Deliver all messages from leader IPC backend to follower
    async fn deliver_leader_to_follower(&mut self) -> usize {
        let outgoing = self.leader_ipc_backend.drain_outgoing().await;
        let count = outgoing.len();
        for outgoing_msg in outgoing {
            let msg = Message::from_cbor(&outgoing_msg.payload)
                .expect("Failed to decode CBOR message from IPC");
            self.follower.receive_message(msg).await.unwrap();
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
async fn test_follower_unlock_propagates_to_leader() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);

    let mut harness = Harness::new(leader_states, follower_states).await;

    // Follower manually unlocks
    harness
        .follower
        .handle_device_event(DeviceEvent::ManualUnlock {
            user_id: user,
            user_key: key.as_bytes().to_vec(),
        })
        .await
        .unwrap();

    harness.pump().await;

    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked {
            user_key: key.clone()
        }
    );
    // Follower also receives the echo back and unlocks locally
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
    assert_eq!(harness.follower_lock.get_state(user), LockState::Locked);
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
            user_key: key.as_bytes().to_vec(),
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
async fn test_heartbeat_round_trip() {
    let user = user_a();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);

    let mut harness = Harness::new(leader_states, follower_states).await;

    // Follower fires Timer → sends HeartBeat for all users
    harness
        .follower
        .handle_device_event(DeviceEvent::Timer)
        .await
        .unwrap();

    harness.pump().await;

    let suppressions = harness.follower_lock.timeout_suppressions.lock().unwrap();
    assert_eq!(suppressions.len(), 1);
    assert_eq!(suppressions[0].0, user);
    assert_eq!(suppressions[0].1, crate::HEARTBEAT_INTERVAL);
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

    // Re-deliver startup messages as a Web source with matching origin
    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://vault.bitwarden.com".to_string(),
    };

    // Manually send a StartSession from the web source
    harness
        .leader
        .receive_message(
            Message::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            web_source,
        )
        .await
        .unwrap();

    // Leader should have accepted the unlock
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

    // Send a StartSession with wrong origin
    harness
        .leader
        .receive_message(
            Message::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            web_source,
        )
        .await
        .unwrap();

    // Leader should have rejected the message and stayed locked
    assert_eq!(harness.leader_lock.get_state(user), LockState::Locked);
}

#[tokio::test]
async fn test_web_source_without_configured_vault_url_is_rejected() {
    let user = user_a();
    let key = test_user_key();
    let leader_states = HashMap::from([(user, LockState::Locked)]);
    let follower_states = HashMap::from([(user, LockState::Locked)]);
    // No vault URLs configured
    let vault_urls = HashMap::new();

    let harness = Harness::new_with_vault_urls(leader_states, follower_states, vault_urls).await;

    let web_source = Source::Web {
        tab_id: 1,
        document_id: "doc-1".to_string(),
        origin: "https://anything.example.com".to_string(),
    };

    harness
        .leader
        .receive_message(
            Message::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            web_source,
        )
        .await
        .unwrap();

    // Should be rejected since no vault URL is configured
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

    // Send a LockStateUpdate (unlock) with wrong origin
    harness
        .leader
        .receive_message(
            Message::LockStateUpdate {
                user_id: user,
                lock_state: LockState::Unlocked { user_key: key },
            },
            web_source,
        )
        .await
        .unwrap();

    // Leader should have rejected the message and stayed locked
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
        .receive_message(
            Message::LockStateUpdate {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            web_source,
        )
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

    // BrowserBackground source has no origin to validate
    let browser_source = Source::BrowserBackground { id: HostId::Own };

    harness
        .leader
        .receive_message(
            Message::StartSession {
                user_id: user,
                lock_state: LockState::Unlocked {
                    user_key: key.clone(),
                },
            },
            browser_source,
        )
        .await
        .unwrap();

    // Should be accepted regardless of vault URL config
    assert_eq!(
        harness.leader_lock.get_state(user),
        LockState::Unlocked { user_key: key }
    );
}
