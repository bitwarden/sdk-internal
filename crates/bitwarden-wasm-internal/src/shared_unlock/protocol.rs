use bitwarden_core::UserId;
use bitwarden_crypto::EncodingError;
use serde::{Deserialize, Serialize};
use tracing::info;
use tsify::Tsify;

use crate::shared_unlock::lock_management::{LockState as UserLockState, UserLockManagement};

pub trait LeaderDiscovery {
    /// Discover the leader and return its endpoint.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}

pub trait MessageSender {
    fn send_message(&self, message: Message, recipient: bitwarden_ipc::Endpoint);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Unlocked { key: Vec<u8> },
}

/// The messages sent between the followers and leader
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    RequestLock {
        user_id: UserId,
    },
    RequestUnlock {
        user_id: UserId,
        user_key: Vec<u8>,
    },
    LockStateUpdate {
        user_id: UserId,
        lock_state: LockState,
    },
    HeartbeatRequest {
        user_id: UserId,
    },
    HeartbeatResponse {
        user_id: UserId,
    },
    StartSession {
        user_id: UserId,
    },
}

impl Message {
    /// Serializes this message to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| EncodingError::InvalidCborSerialization)?;
        Ok(buffer)
    }

    /// Deserializes a message from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, EncodingError> {
        ciborium::de::from_reader(data).map_err(|_| EncodingError::InvalidCborSerialization)
    }
}

/// The device (client) has several events that need to be reported to the shared unlock system.
/// This enum represents the events that need to be reported.
#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum DeviceEvents {
    /// The user with the given user id has been locked manually in the UI
    ManualLock { user_id: UserId },
    /// The user with the given user id has been unlocked manually in the UI
    ManualUnlock { user_id: UserId, user_key: Vec<u8> },
    /// Runs scheduled every 1 minute, to drive keep-alives
    Timer,
}

pub(crate) struct Follower<L: UserLockManagement, S: MessageSender, D: LeaderDiscovery> {
    lock_system: L,
    leader_discovery: D,
    _phantom: std::marker::PhantomData<S>,
}

impl<L: UserLockManagement, S: MessageSender, D: LeaderDiscovery> Follower<L, S, D> {
    pub async fn create(lock_system: L, leader_discovery: D) -> Self {
        Self {
            lock_system,
            leader_discovery,
            _phantom: std::marker::PhantomData,
        }
    }

    pub async fn receive_message(&self, message: Message) -> Result<(), ()> {
        match message {
            Message::LockStateUpdate {
                user_id,
                lock_state,
            } => {
                let current_state = self.lock_system.get_user_lock_state(user_id).await;

                match (current_state, lock_state) {
                    (UserLockState::Locked, LockState::Locked) => Ok(()),
                    (UserLockState::Unlocked { .. }, LockState::Locked) => {
                        self.lock_system.lock_user(user_id).await
                    }
                    (UserLockState::Locked, LockState::Unlocked { key }) => {
                        self.lock_system.unlock_user(user_id, key).await
                    }
                    (
                        UserLockState::Unlocked { key: current_key },
                        LockState::Unlocked { key },
                    ) => {
                        if current_key == key {
                            Ok(())
                        } else {
                            self.lock_system.unlock_user(user_id, key).await
                        }
                    }
                }
            }
            Message::HeartbeatResponse { user_id } => {
                info!("Received heartbeat response for user_id: {:?}", user_id);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub async fn handle_device_event(&self, event: DeviceEvents, sender: S) -> Result<(), ()> {
        let leader = self.leader_discovery.discover_leader().await.ok_or(())?;

        match event {
            DeviceEvents::ManualLock { user_id } => {
                let message = Message::RequestLock { user_id };
                sender.send_message(message, leader);
                Ok(())
            }
            DeviceEvents::ManualUnlock { user_id, user_key } => {
                let message = Message::RequestUnlock { user_id, user_key };
                sender.send_message(message, leader);
                Ok(())
            }
            DeviceEvents::Timer => {
                let user_ids = self.lock_system.list_users().await;
                info!("Timer event: sending heartbeat for users: {:?}", user_ids);
                info!("Leader endpoint: {:?}", leader);
                for user_id in user_ids {
                    let message = Message::HeartbeatRequest { user_id };
                    sender.send_message(message, leader.clone());
                }
                Ok(())
            }
        }
    }
}

pub(crate) struct Leader<L: UserLockManagement, S: MessageSender> {
    message_sender: S,
    lock_system: L,
}

impl<L: UserLockManagement, S: MessageSender> Leader<L, S> {
    pub fn create(lock_system: L, message_sender: S) -> Self {
        Self {
            message_sender,
            lock_system,
        }
    }

    pub async fn handle_device_event(&self, event: DeviceEvents) -> Result<(), ()> {
        match event {
            DeviceEvents::ManualLock { user_id } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };

                self.message_sender
                    .send_message(message, bitwarden_ipc::Endpoint::BrowserForeground);
                Ok(())
            }
            DeviceEvents::ManualUnlock { user_id, user_key } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked { key: user_key },
                };

                self.message_sender
                    .send_message(message, bitwarden_ipc::Endpoint::BrowserForeground);
                Ok(())
            }
            DeviceEvents::Timer => Ok(()),
        }
    }

    pub async fn receive_message(
        &self,
        message: Message,
        sender: bitwarden_ipc::Endpoint,
    ) -> Result<(), ()> {
        match message {
            Message::RequestLock { user_id } => {
                self.lock_system.lock_user(user_id).await?;
                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::RequestUnlock { user_id, user_key } => {
                self.lock_system
                    .unlock_user(user_id, user_key.clone())
                    .await?;
                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked { key: user_key },
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::HeartbeatRequest { user_id } | Message::StartSession { user_id } => {
                self.message_sender
                    .send_message(Message::HeartbeatResponse { user_id }, sender);
                Ok(())
            }
            Message::HeartbeatResponse { .. } | Message::LockStateUpdate { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use bitwarden_ipc::Endpoint;
    use tokio::sync::Mutex;

    use super::*;
    use crate::shared_unlock::lock_management::LockState as UserLockState;

    #[derive(Clone, Default)]
    struct MockUserLockManagement {
        users: Arc<Mutex<HashMap<UserId, Option<Vec<u8>>>>>,
        lock_calls: Arc<AtomicUsize>,
        unlock_calls: Arc<AtomicUsize>,
    }

    impl MockUserLockManagement {
        async fn lock_state(&self, user_id: UserId) -> UserLockState {
            self.get_user_lock_state(user_id).await
        }

        fn lock_calls(&self) -> usize {
            self.lock_calls.load(Ordering::SeqCst)
        }

        fn unlock_calls(&self) -> usize {
            self.unlock_calls.load(Ordering::SeqCst)
        }
    }

    impl UserLockManagement for MockUserLockManagement {
        async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
            self.lock_calls.fetch_add(1, Ordering::SeqCst);
            let mut users = self.users.lock().await;
            users.insert(user_id, None);
            Ok(())
        }

        async fn unlock_user(&self, user_id: UserId, user_key: Vec<u8>) -> Result<(), ()> {
            self.unlock_calls.fetch_add(1, Ordering::SeqCst);
            let mut users = self.users.lock().await;
            users.insert(user_id, Some(user_key));
            Ok(())
        }

        async fn list_users(&self) -> Vec<UserId> {
            let users = self.users.lock().await;
            users.keys().copied().collect()
        }

        async fn get_user_lock_state(&self, user_id: UserId) -> UserLockState {
            let users = self.users.lock().await;
            match users.get(&user_id) {
                Some(Some(key)) => UserLockState::Unlocked { key: key.clone() },
                _ => UserLockState::Locked,
            }
        }
    }

    #[derive(Clone, Default)]
    struct MockMessageSender {
        sent_messages: Arc<std::sync::Mutex<Vec<(Message, Endpoint)>>>,
    }

    impl MockMessageSender {
        fn messages(&self) -> Vec<(Message, Endpoint)> {
            let guard = match self.sent_messages.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.clone()
        }
    }

    impl MessageSender for MockMessageSender {
        fn send_message(&self, message: Message, recipient: Endpoint) {
            let mut guard = match self.sent_messages.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push((message, recipient));
        }
    }

    struct MockLeaderDiscovery {
        leader: Endpoint,
    }

    impl LeaderDiscovery for MockLeaderDiscovery {
        async fn discover_leader(&self) -> Option<Endpoint> {
            Some(self.leader)
        }
    }

    #[tokio::test]
    async fn leader_replies_to_heartbeat_request() {
        let lock_system = MockUserLockManagement::default();
        let sender = MockMessageSender::default();
        let leader = Leader::create(lock_system, sender.clone());
        let user_id = UserId::new_v4();
        let source = Endpoint::DesktopRenderer;

        let result = leader
            .receive_message(Message::HeartbeatRequest { user_id }, source)
            .await;

        assert!(result.is_ok());
        assert_eq!(
            sender.messages(),
            vec![(Message::HeartbeatResponse { user_id }, source)]
        );
    }

    #[tokio::test]
    async fn leader_replies_to_start_session() {
        let lock_system = MockUserLockManagement::default();
        let sender = MockMessageSender::default();
        let leader = Leader::create(lock_system, sender.clone());
        let user_id = UserId::new_v4();
        let source = Endpoint::DesktopMain;

        let result = leader
            .receive_message(Message::StartSession { user_id }, source)
            .await;

        assert!(result.is_ok());
        assert_eq!(
            sender.messages(),
            vec![(Message::HeartbeatResponse { user_id }, source)]
        );
    }

    #[tokio::test]
    async fn leader_handles_manual_lock_device_event() {
        let lock_system = MockUserLockManagement::default();
        let sender = MockMessageSender::default();
        let leader = Leader::create(lock_system.clone(), sender.clone());
        let user_id = UserId::new_v4();
        let user_key = vec![9, 8, 7, 6];

        let init_result = lock_system.unlock_user(user_id, user_key).await;
        assert!(init_result.is_ok());

        let result = leader
            .handle_device_event(DeviceEvents::ManualLock { user_id })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            lock_system.lock_state(user_id).await,
            UserLockState::Unlocked { key } if key == vec![9, 8, 7, 6]
        ));
        assert_eq!(
            sender.messages(),
            vec![
                (
                    Message::LockStateUpdate {
                        user_id,
                        lock_state: LockState::Locked,
                    },
                    Endpoint::BrowserForeground,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn leader_handles_manual_unlock_device_event() {
        let lock_system = MockUserLockManagement::default();
        let sender = MockMessageSender::default();
        let leader = Leader::create(lock_system.clone(), sender.clone());
        let user_id = UserId::new_v4();
        let user_key = vec![4, 5, 6, 7];

        let init_result = lock_system.lock_user(user_id).await;
        assert!(init_result.is_ok());

        let result = leader
            .handle_device_event(DeviceEvents::ManualUnlock {
                user_id,
                user_key: user_key.clone(),
            })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            lock_system.lock_state(user_id).await,
            UserLockState::Locked
        ));
        assert_eq!(
            sender.messages(),
            vec![
                (
                    Message::LockStateUpdate {
                        user_id,
                        lock_state: LockState::Unlocked {
                            key: user_key,
                        },
                    },
                    Endpoint::BrowserForeground,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn follower_applies_lock_state_only_when_needed() {
        let user_id = UserId::new_v4();
        let key = vec![1, 2, 3, 4];
        let lock_system = MockUserLockManagement::default();
        let sender = MockMessageSender::default();
        let follower =
            Follower::<MockUserLockManagement, MockMessageSender, MockLeaderDiscovery>::create(
                lock_system.clone(),
                MockLeaderDiscovery {
                    leader: Endpoint::BrowserBackground,
                },
            )
            .await;

        let initial_unlock_result = lock_system.unlock_user(user_id, key.clone()).await;
        assert!(initial_unlock_result.is_ok());
        assert_eq!(lock_system.unlock_calls(), 1);

        let same_state_result = follower
            .receive_message(Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Unlocked { key: key.clone() },
            })
            .await;
        assert!(same_state_result.is_ok());
        assert_eq!(lock_system.unlock_calls(), 1);

        let lock_result = follower
            .receive_message(Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Locked,
            })
            .await;
        assert!(lock_result.is_ok());
        assert_eq!(lock_system.lock_calls(), 1);

        let redundant_lock_result = follower
            .receive_message(Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Locked,
            })
            .await;
        assert!(redundant_lock_result.is_ok());
        assert_eq!(lock_system.lock_calls(), 1);

        assert!(sender.messages().is_empty());
    }

    #[tokio::test]
    async fn leader_and_follower_unlock_roundtrip_updates_both_sides() {
        let user_id = UserId::new_v4();
        let user_key = vec![1, 2, 3, 4, 5, 6];

        let follower_lock_system = MockUserLockManagement::default();
        let leader_lock_system = MockUserLockManagement::default();
        let follower_init = follower_lock_system.lock_user(user_id).await;
        let leader_init = leader_lock_system.lock_user(user_id).await;

        assert!(follower_init.is_ok());
        assert!(leader_init.is_ok());

        let follower_sender = MockMessageSender::default();
        let leader_sender = MockMessageSender::default();

        let follower =
            Follower::<MockUserLockManagement, MockMessageSender, MockLeaderDiscovery>::create(
                follower_lock_system.clone(),
                MockLeaderDiscovery {
                    leader: Endpoint::BrowserBackground,
                },
            )
            .await;

        let leader = Leader::create(leader_lock_system.clone(), leader_sender.clone());

        let follower_result = follower
            .handle_device_event(
                DeviceEvents::ManualUnlock {
                    user_id,
                    user_key: user_key.clone(),
                },
                follower_sender.clone(),
            )
            .await;

        assert!(follower_result.is_ok());

        let follower_messages = follower_sender.messages();
        assert_eq!(follower_messages.len(), 1);

        let (request_message, destination) = follower_messages[0].clone();
        assert_eq!(destination, Endpoint::BrowserBackground);
        assert_eq!(
            request_message,
            Message::RequestUnlock {
                user_id,
                user_key: user_key.clone(),
            }
        );

        let source = Endpoint::Web { id: 42 };
        let leader_result = leader.receive_message(request_message, source).await;
        assert!(leader_result.is_ok());

        let leader_messages = leader_sender.messages();
        assert_eq!(leader_messages.len(), 1);

        let (leader_response, response_destination) = leader_messages[0].clone();
        assert_eq!(response_destination, source);
        assert_eq!(
            leader_response,
            Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Unlocked {
                    key: user_key.clone(),
                },
            }
        );

        let apply_result = follower.receive_message(leader_response).await;
        assert!(apply_result.is_ok());

        let follower_state = follower_lock_system.lock_state(user_id).await;
        let leader_state = leader_lock_system.lock_state(user_id).await;

        assert!(matches!(
            follower_state,
            UserLockState::Unlocked { key } if key == user_key
        ));
        assert!(matches!(
            leader_state,
            UserLockState::Unlocked { key } if key == user_key
        ));
    }
}
