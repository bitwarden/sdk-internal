use std::sync::Arc;

use bitwarden_ipc::{Endpoint, IpcClient, OutgoingMessage};

use crate::{
    DeviceEvent, LockState, Message,
    drivers::{HeartbeatResponseHandler, LeaderDiscovery, UserLockManagement},
};

/// Tracks local state and follows authoritative lock updates from a leader.
pub struct Follower<L: UserLockManagement, D: LeaderDiscovery, H: HeartbeatResponseHandler> {
    lock_system: L,
    leader_discovery: D,
    heartbeat_response_handler: H,
    ipc_client: Arc<dyn IpcClient>,
}

impl<L: UserLockManagement, D: LeaderDiscovery, H: HeartbeatResponseHandler> Follower<L, D, H> {
    /// Creates a follower instance and starts sessions for all currently known users.
    ///
    /// During startup, a `StartSession` message is sent per user so the leader can reconcile
    /// initial lock state.
    pub async fn create(
        lock_system: L,
        leader_discovery: D,
        heartbeat_response_handler: H,
        ipc_client: Arc<dyn IpcClient>,
    ) -> Self {
        let follower = Self {
            lock_system,
            leader_discovery,
            heartbeat_response_handler,
            ipc_client,
        };
        follower.start_sessions().await;
        follower
    }

    async fn start_sessions(&self) {
        let users: Vec<bitwarden_core::UserId> = self.lock_system.list_users().await;
        let leader = self
            .leader_discovery
            .discover_leader()
            .await
            .expect("leader discovery should return a leader");

        for user_id in users {
            let lock_state = self.lock_system.get_user_lock_state(user_id).await;
            let message = Message::StartSession {
                user_id,
                lock_state,
            };
            self.send_message(message, leader.clone()).await;
        }
    }

    /// Handles an authoritative message from the leader.
    ///
    /// Lock state updates overwrite local state to keep follower and leader in sync. Heartbeat
    /// responses are forwarded to the heartbeat response handler.
    pub async fn receive_message(&self, message: Message) -> Result<(), ()> {
        match message {
            Message::LockStateUpdate {
                user_id,
                lock_state,
            } => {
                // The leader is the authoritative state source for the follow, and it should
                // always overwrite the local state of the follower.
                let current_state = self.lock_system.get_user_lock_state(user_id).await;

                match (current_state, lock_state) {
                    (LockState::Unlocked { .. }, LockState::Locked) => {
                        // If the user is currently unlocked and it receives an authoritative lock
                        // state update from the leader that is Locked, then
                        // it should follow, and lock the local state.
                        self.lock_system.lock_user(user_id).await?
                    }
                    (LockState::Locked, LockState::Unlocked { user_key }) => {
                        // If the user is currently locked and it receives an authoritative lock
                        // state update from the leader that is Unlocked,
                        // then it should follow, and unlock the local state.
                        self.lock_system.unlock_user(user_id, user_key).await?;
                    }
                    (LockState::Locked, LockState::Locked)
                    | (LockState::Unlocked { .. }, LockState::Unlocked { .. }) => {
                        // If both the current state and the received lock state are the same, then
                        // do nothing, as they are already in sync.
                    }
                }
            }
            Message::HeartBeat { user_id } => {
                self.heartbeat_response_handler
                    .handle_heartbeat(user_id)
                    .await;
            }
            _ => {}
        }

        Ok(())
    }

    /// Handles local device events and forwards them to the discovered leader.
    ///
    /// Manual lock/unlock events are sent as lock state updates. Timer events send per-user
    /// heartbeats to keep the shared session active.
    pub async fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        let leader = self.leader_discovery.discover_leader().await.ok_or(())?;

        match event {
            DeviceEvent::ManualLock { user_id } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.send_message(message, leader).await;
            }
            DeviceEvent::ManualUnlock { user_id, user_key } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: super::UserKey::from_bytes(user_key),
                    },
                };
                self.send_message(message, leader).await;
            }
            DeviceEvent::Timer => {
                // For all users that are logged in, send a heartbeat message to the leader.
                for user_id in self.lock_system.list_users().await {
                    let message = Message::HeartBeat { user_id };
                    self.send_message(message, leader.clone()).await;
                }
            }
        }

        Ok(())
    }

    async fn send_message(&self, message: Message, recipient: Endpoint) {
        let payload = match message.to_cbor() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(?error, "Failed to serialize shared unlock IPC message");
                return;
            }
        };

        let outgoing_message = OutgoingMessage {
            payload,
            destination: recipient,
            topic: Some("password-manager.shared-unlock.follower-to-leader".to_string()),
        };

        if let Err(error) = self.ipc_client.send(outgoing_message).await {
            tracing::error!(?error, "Failed to send shared unlock IPC message");
        }
    }
}
