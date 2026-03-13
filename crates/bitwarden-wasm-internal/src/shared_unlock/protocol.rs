use bitwarden_core::UserId;
use bitwarden_crypto::EncodingError;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::shared_unlock::lock_management::UserLockManagement;

pub trait LeaderDiscovery {
    /// Discover the leader and return its endpoint.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}

pub trait MessageSender {
    fn send_message(&self, message: Message, recipient: bitwarden_ipc::Endpoint);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Unlocked { key: Vec<u8> },
}

/// The messages sent between the followers and leader
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
            } => match lock_state {
                LockState::Locked => self.lock_system.lock_user(user_id).await,
                LockState::Unlocked { key } => self.lock_system.unlock_user(user_id, key).await,
            },
            _ => Ok(()),
        }
    }

    pub async fn handle_device_event(&self, event: DeviceEvents, sender: S) -> Result<(), ()> {
        let leader = self.leader_discovery.discover_leader().await.unwrap();

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
                for user_id in user_ids {
                    let message = Message::HeartbeatRequest { user_id };
                    sender.send_message(message, leader.clone());
                }
                Ok(())
            }
        }
    }
}

struct Leader<L: UserLockManagement, S: MessageSender> {
    message_sender: S,
    lock_system: L,
}

impl<L: UserLockManagement, S: MessageSender> Leader<L, S> {
    async fn receive_message(
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
                self.lock_system.unlock_user(user_id, user_key).await?;
                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked { key: vec![] },
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::HeartbeatRequest { .. } | Message::HeartbeatResponse { .. } => Ok(()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user_id() -> UserId {
        "00000000-0000-0000-0000-000000000001"
            .parse()
            .expect("static test UUID should be a valid UserId")
    }

    #[test]
    fn message_cbor_roundtrip() {
        let message = Message::RequestUnlock {
            user_id: test_user_id(),
            user_key: vec![1, 2, 3, 4],
        };

        let encoded = message
            .to_cbor()
            .expect("message should serialize to valid CBOR");
        let decoded = Message::from_cbor(&encoded).expect("encoded message should decode");

        assert_eq!(message, decoded);
    }

    #[test]
    fn message_cbor_decode_fails_for_invalid_bytes() {
        let invalid_cbor = [0xff];
        let result = Message::from_cbor(&invalid_cbor);

        assert!(matches!(
            result,
            Err(EncodingError::InvalidCborSerialization)
        ));
    }
}
