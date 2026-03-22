use crate::shared_unlock::protocol::{
    DeviceEvent, LockState,
    drivers::{HeartbeatResponseHandler, LeaderDiscovery, MessageSender, UserLockManagement},
    protocol::Message,
};

pub(crate) struct Follower<
    L: UserLockManagement,
    S: MessageSender,
    D: LeaderDiscovery,
    H: HeartbeatResponseHandler,
> {
    lock_system: L,
    leader_discovery: D,
    heartbeat_response_handler: H,
    sender: S,
}

impl<L: UserLockManagement, S: MessageSender, D: LeaderDiscovery, H: HeartbeatResponseHandler>
    Follower<L, S, D, H>
{
    pub async fn create(
        lock_system: L,
        leader_discovery: D,
        heartbeat_response_handler: H,
        sender: S,
    ) -> Self {
        Self::start_sessions(&lock_system, &leader_discovery, &sender).await;

        Self {
            lock_system,
            leader_discovery,
            heartbeat_response_handler,
            sender,
        }
    }

    async fn start_sessions(lock_system: &L, leader_discovery: &D, sender: &S) {
        let users: Vec<bitwarden_core::UserId> = lock_system.list_users().await;
        let leader = leader_discovery.discover_leader().await.unwrap();

        for user_id in users {
            let lock_state = lock_system.get_user_lock_state(user_id).await;
            let message = Message::StartSession {
                user_id,
                lock_state,
            };
            sender.send_message(message, leader);
        }
    }

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

    pub async fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        let leader = self.leader_discovery.discover_leader().await.ok_or(())?;

        match event {
            DeviceEvent::ManualLock { user_id } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.sender.send_message(message, leader);
            }
            DeviceEvent::ManualUnlock { user_id, user_key } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: super::UserKey::from_bytes(user_key),
                    },
                };
                self.sender.send_message(message, leader);
            }
            DeviceEvent::Timer => {
                // For all users that are logged in, send a heartbeat message to the leader.
                for user_id in self.lock_system.list_users().await {
                    let message = Message::HeartBeat { user_id };
                    self.sender.send_message(message, leader);
                }
            }
        }

        Ok(())
    }
}
