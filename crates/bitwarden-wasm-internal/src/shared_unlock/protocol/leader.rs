use std::{collections::HashMap, sync::Mutex, time::Duration};

use tracing::{debug, info, warn};

use crate::shared_unlock::protocol::{
    DeviceEvent, LockState, Message, UserKey,
    drivers::{MessageSender, UserLockManagement},
};

const FOLLOWER_STALE_AFTER: Duration = Duration::from_secs(120);

struct FollowerSession {
    last_seen_at: u64,
}

struct FollowerSessions {
    sessions: Mutex<HashMap<bitwarden_ipc::Endpoint, FollowerSession>>,
}

impl FollowerSessions {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn upsert(&self, endpoint: bitwarden_ipc::Endpoint, seen_at: u64) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if !sessions.contains_key(&endpoint) {
            info!("shared unlock client connected {:?}", endpoint);
        }

        sessions.insert(
            endpoint,
            FollowerSession {
                last_seen_at: seen_at,
            },
        );
    }

    fn active_endpoints(&self) -> Vec<bitwarden_ipc::Endpoint> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        sessions.keys().copied().collect()
    }

    fn prune_stale(&self, now: u64, stale_after: Duration) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let stale_after_millis = stale_after.as_millis() as u64;
        for (endpoint, session) in sessions.iter() {
            if now.saturating_sub(session.last_seen_at) > stale_after_millis {
                info!("shared unlock client {:?} is stale, removing", endpoint);
            }
        }
        sessions
            .retain(|_, session| now.saturating_sub(session.last_seen_at) <= stale_after_millis);
    }
}

pub(crate) struct Leader<L: UserLockManagement, S: MessageSender> {
    message_sender: S,
    lock_system: L,
    follower_sessions: FollowerSessions,
}

impl<L: UserLockManagement, S: MessageSender> Leader<L, S> {
    pub fn create(lock_system: L, message_sender: S) -> Self {
        Self {
            message_sender,
            lock_system,
            follower_sessions: FollowerSessions::new(),
        }
    }

    fn broadcast_to_active_followers(&self, message: Message) {
        let endpoints = self.follower_sessions.active_endpoints();
        for endpoint in endpoints {
            self.message_sender.send_message(message.clone(), endpoint);
        }
    }

    pub async fn receive_message(
        &self,
        message: Message,
        sender: bitwarden_ipc::Endpoint,
    ) -> Result<(), ()> {
        info!(?sender, "Received message from follower: {:?}", message);
        match message {
            Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Locked,
            } => {
                info!(?sender, %user_id, "Received lock request from follower");
                self.follower_sessions
                    .upsert(sender, get_current_timestamp());

                self.lock_system
                    .lock_user(user_id)
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to lock user"))?;
                info!(%user_id, "User locked, sending confirmation to follower");
                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::LockStateUpdate {
                user_id,
                lock_state: LockState::Unlocked { user_key },
            } => {
                info!(?sender, %user_id, "Received unlock request from follower");
                self.follower_sessions
                    .upsert(sender, get_current_timestamp());

                self.lock_system
                    .unlock_user(user_id, user_key.clone())
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to unlock user"))?;
                info!(%user_id, "User unlocked, sending confirmation to follower");
                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked { user_key },
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::StartSession {
                user_id,
                lock_state,
            } => {
                info!(?sender, %user_id, "Received start session from follower");
                self.follower_sessions
                    .upsert(sender, get_current_timestamp());

                let response_lock_state = match lock_state {
                    LockState::Unlocked { user_key } => {
                        self.lock_system
                            .unlock_user(user_id, user_key.clone())
                            .await
                            .inspect_err(
                                |_| warn!(%user_id, "Failed to unlock user during start session"),
                            )?;
                        info!(%user_id, "User unlocked during start session");
                        LockState::Unlocked { user_key }
                    }
                    LockState::Locked => {
                        self.lock_system.lock_user(user_id).await.inspect_err(
                            |_| warn!(%user_id, "Failed to lock user during start session"),
                        )?;
                        info!(%user_id, "User locked during start session");
                        LockState::Locked
                    }
                };

                let response = Message::LockStateUpdate {
                    user_id,
                    lock_state: response_lock_state,
                };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
            Message::HeartBeat { user_id } => {
                info!(?sender, %user_id, "Received heartbeat from follower");
                self.follower_sessions
                    .upsert(sender, get_current_timestamp());

                let response = Message::HeartBeat { user_id };
                self.message_sender.send_message(response, sender);
                Ok(())
            }
        }
    }

    pub fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        match event {
            DeviceEvent::ManualLock { user_id } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.broadcast_to_active_followers(message);
            }
            DeviceEvent::ManualUnlock { user_id, user_key } => {
                let message = Message::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: UserKey::from_bytes(user_key),
                    },
                };
                self.broadcast_to_active_followers(message);
            }
            DeviceEvent::Timer => {
                self.follower_sessions
                    .prune_stale(get_current_timestamp(), FOLLOWER_STALE_AFTER);
            }
        }

        Ok(())
    }
}

fn get_current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::js_sys::Date::now() as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_millis() as u64
    }
}
