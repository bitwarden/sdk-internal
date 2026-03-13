use bitwarden_core::UserId;
use serde::{Deserialize, Serialize};

use crate::shared_unlock::lock_management::UserLockManagement;

pub trait LeaderDiscovery {
    /// Discover the leader and return its endpoint.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}

pub trait MessageSender {
    fn send_message(&self, message: Message, recipient: bitwarden_ipc::Endpoint);
}

#[derive(Serialize, Deserialize)]
pub enum LockState {
    Locked,
    Unlocked { key: Vec<u8> },
}

/// The messages sent between the followers and leader
#[derive(Serialize, Deserialize)]
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
}

/// The device (client) has several events that need to be reported to the shared unlock system.
/// This enum represents the events that need to be reported.
pub enum DeviceEvents {
    /// The user with the given user id has been locked manually in the UI
    ManualLock { user_id: UserId },
    /// The user with the given user id has been unlocked manually in the UI
    ManualUnlock { user_id: UserId, user_key: Vec<u8> },
    /// Runs scheduled every 1 minute, to drive keep-alives
    Timer,
}

struct Follower<L: UserLockManagement, S: MessageSender, D: LeaderDiscovery> {
    message_sender: S,
    lock_system: L,
    leader_discovery: D,
}

impl<L: UserLockManagement, S: MessageSender, D: LeaderDiscovery> Follower<L, S, D> {
    async fn receive_message(&self, message: Message) -> Result<(), ()> {
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
    async fn handle_device_event(&self, event: DeviceEvents) -> Result<(), ()> {
        let leader = self.leader_discovery.discover_leader().await.unwrap();
        match event {
            DeviceEvents::ManualLock { user_id } => {
                let message = Message::RequestLock { user_id };
                self.message_sender.send_message(message, leader);
                Ok(())
            }
            DeviceEvents::ManualUnlock { user_id, user_key } => {
                let message = Message::RequestUnlock { user_id, user_key };
                self.message_sender.send_message(message, leader);
                Ok(())
            }
            DeviceEvents::Timer => {
                let user_ids = self.lock_system.list_users().await;
                for user_id in user_ids {
                    let message = Message::HeartbeatRequest { user_id };
                    self.message_sender.send_message(message, leader.clone());
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
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_setup() {}
}
