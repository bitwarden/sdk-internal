use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitwarden_core::UserId;
use bitwarden_ipc::Endpoint;

use super::{
    DeviceEvent, Follower, Leader, LockState, Message, UserKey,
    drivers::{HeartbeatResponseHandler, LeaderDiscovery, MessageSender, UserLockManagement},
};

#[derive(Clone)]
struct MockLockSystem {
    states: Arc<Mutex<HashMap<UserId, LockState>>>,
}

impl MockLockSystem {
    fn new(initial: HashMap<UserId, LockState>) -> Self {
        Self {
            states: Arc::new(Mutex::new(initial)),
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
}

#[derive(Clone)]
struct MockMessageSender {
    outbox: Arc<Mutex<Vec<(Message, Endpoint)>>>,
}

impl MockMessageSender {
    fn new() -> Self {
        Self {
            outbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn drain(&self) -> Vec<(Message, Endpoint)> {
        self.outbox.lock().unwrap().drain(..).collect()
    }
}

impl MessageSender for MockMessageSender {
    fn send_message(&self, message: Message, recipient: Endpoint) {
        self.outbox.lock().unwrap().push((message, recipient));
    }
}

struct MockLeaderDiscovery {
    endpoint: Endpoint,
}

impl LeaderDiscovery for MockLeaderDiscovery {
    async fn discover_leader(&self) -> Option<Endpoint> {
        Some(self.endpoint)
    }
}

struct MockHeartbeatHandler {
    heartbeats: Arc<Mutex<Vec<UserId>>>,
}

impl MockHeartbeatHandler {
    fn new() -> Self {
        Self {
            heartbeats: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl HeartbeatResponseHandler for MockHeartbeatHandler {
    async fn handle_heartbeat(&self, user_id: UserId) {
        self.heartbeats.lock().unwrap().push(user_id);
    }
}

const LEADER_ENDPOINT: Endpoint = Endpoint::DesktopMain;
const FOLLOWER_ENDPOINT: Endpoint = Endpoint::BrowserBackground;

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
    leader: Leader<MockLockSystem, MockMessageSender>,
    follower:
        Follower<MockLockSystem, MockMessageSender, MockLeaderDiscovery, MockHeartbeatHandler>,
    leader_lock: MockLockSystem,
    follower_lock: MockLockSystem,
    leader_outbox: MockMessageSender,
    follower_outbox: MockMessageSender,
    heartbeat_handler: Arc<Mutex<Vec<UserId>>>,
}

impl Harness {
    async fn new(
        leader_states: HashMap<UserId, LockState>,
        follower_states: HashMap<UserId, LockState>,
    ) -> Self {
        let leader_lock = MockLockSystem::new(leader_states);
        let leader_outbox = MockMessageSender::new();
        let leader = Leader::create(leader_lock.clone(), leader_outbox.clone());

        let follower_lock = MockLockSystem::new(follower_states);
        let follower_outbox = MockMessageSender::new();
        let heartbeat_handler = MockHeartbeatHandler::new();
        let heartbeats = heartbeat_handler.heartbeats.clone();

        let follower = Follower::create(
            follower_lock.clone(),
            MockLeaderDiscovery {
                endpoint: LEADER_ENDPOINT,
            },
            heartbeat_handler,
            follower_outbox.clone(),
        )
        .await;

        let mut harness = Self {
            leader,
            follower,
            leader_lock,
            follower_lock,
            leader_outbox,
            follower_outbox,
            heartbeat_handler: heartbeats,
        };

        // Pump startup messages (StartSession -> LockStateUpdate responses)
        harness.pump().await;
        harness
    }

    /// Deliver all messages from follower outbox to leader
    async fn deliver_follower_to_leader(&mut self) -> usize {
        let messages = self.follower_outbox.drain();
        let count = messages.len();
        for (msg, _recipient) in messages {
            self.leader
                .receive_message(msg, FOLLOWER_ENDPOINT)
                .await
                .unwrap();
        }
        count
    }

    /// Deliver all messages from leader outbox to follower
    async fn deliver_leader_to_follower(&mut self) -> usize {
        let messages = self.leader_outbox.drain();
        let count = messages.len();
        for (msg, _recipient) in messages {
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

    let heartbeats = harness.heartbeat_handler.lock().unwrap();
    assert_eq!(*heartbeats, vec![user]);
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
