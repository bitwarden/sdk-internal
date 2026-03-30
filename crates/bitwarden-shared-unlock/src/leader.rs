use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_ipc::{Endpoint, IpcClient, IpcClientExt, TypedIncomingMessage};
use tracing::{info, warn};

use crate::{
    DeviceEvent, FollowerMessage, LeaderMessage, LockState, UserKey, drivers::UserLockManagement,
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

        sessions.keys().cloned().collect()
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

/// Coordinates shared unlock state as the authoritative endpoint for followers.
pub struct Leader<L: UserLockManagement> {
    lock_system: L,
    follower_sessions: FollowerSessions,
    ipc_client: Arc<dyn IpcClient>,
}

impl<L: UserLockManagement> Leader<L> {
    /// Creates a leader instance for the shared unlock protocol.
    pub fn create(lock_system: L, ipc_client: Arc<dyn IpcClient>) -> Self {
        Self {
            lock_system,
            follower_sessions: FollowerSessions::new(),
            ipc_client,
        }
    }

    async fn broadcast_to_active_followers(&self, message: LeaderMessage) {
        let endpoints = self.follower_sessions.active_endpoints();
        for endpoint in endpoints {
            self.send_message(message.clone(), endpoint).await;
        }
    }

    /// Handles a message sent by a follower.
    ///
    /// This updates follower session liveness, validates web message origins against the
    /// follower user's vault URL, and applies lock state changes when needed.
    pub async fn receive_message(
        &self,
        incoming_message: TypedIncomingMessage<FollowerMessage>,
    ) -> Result<(), ()> {
        let message = incoming_message.payload;
        let sender = incoming_message.source;

        info!(?sender, "Received message from follower: {:?}", message);
        let endpoint: bitwarden_ipc::Endpoint = sender.clone().into();

        // Validate the origin of web sources against the user's vault URL
        if let bitwarden_ipc::Source::Web { origin, .. } = &sender {
            let user_id = message.user_id();
            match self.lock_system.get_vault_url(user_id).await {
                Some(user_vault_url) if origin == &user_vault_url => {}
                Some(user_vault_url) => {
                    warn!(%origin, %user_vault_url, "IPC message origin does not match user's vault URL, ignoring message");
                    return Ok(());
                }
                None => {
                    warn!(%origin, "No vault URL found for user, ignoring message");
                    return Ok(());
                }
            }
        }

        match message {
            FollowerMessage::LockStateUpdate {
                user_id,
                lock_state: LockState::Locked,
            } => {
                info!(?sender, %user_id, "Received lock request from follower");
                self.follower_sessions
                    .upsert(endpoint.clone(), get_current_timestamp());

                let self_lock_state = self.lock_system.get_user_lock_state(user_id).await;
                if self_lock_state == LockState::Locked {
                    return Ok(());
                }

                self.lock_system
                    .lock_user(user_id)
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to lock user"))?;
                info!(%user_id, "User locked, sending confirmation to follower");
                let response = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.send_message(response, endpoint.clone()).await;
                Ok(())
            }
            FollowerMessage::LockStateUpdate {
                user_id,
                lock_state: LockState::Unlocked { user_key },
            } => {
                info!(?sender, %user_id, "Received unlock request from follower");
                self.follower_sessions
                    .upsert(endpoint.clone(), get_current_timestamp());

                let self_lock_state = self.lock_system.get_user_lock_state(user_id).await;
                if let LockState::Unlocked { .. } = self_lock_state {
                    return Ok(());
                }

                self.lock_system
                    .unlock_user(user_id, user_key.clone())
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to unlock user"))?;
                info!(%user_id, "User unlocked, sending confirmation to follower");
                let response = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked { user_key },
                };
                self.send_message(response, endpoint.clone()).await;
                Ok(())
            }
            FollowerMessage::StartSession {
                user_id,
                lock_state,
            } => {
                info!(?sender, %user_id, "Received start session from follower");

                self.follower_sessions
                    .upsert(endpoint.clone(), get_current_timestamp());
                let self_lock_state = self.lock_system.get_user_lock_state(user_id).await;

                match (lock_state, self_lock_state.clone()) {
                    (LockState::Unlocked { user_key }, LockState::Locked { .. }) => {
                        self.lock_system
                            .unlock_user(user_id, user_key.clone())
                            .await
                            .inspect_err(
                                |_| warn!(%user_id, "Failed to unlock user during start session"),
                            )?;
                    }
                    (LockState::Locked, LockState::Unlocked { .. }) => {
                        let response = LeaderMessage::LockStateUpdate {
                            user_id,
                            lock_state: self_lock_state,
                        };
                        self.send_message(response, endpoint.clone()).await;
                    }
                    _ => {
                        // States are already in sync, no action needed
                    }
                };

                Ok(())
            }
            FollowerMessage::HeartBeat { user_id } => {
                info!(?sender, %user_id, "Received heartbeat from follower");
                self.follower_sessions
                    .upsert(endpoint.clone(), get_current_timestamp());

                let response = LeaderMessage::HeartBeat { user_id };
                self.send_message(response, endpoint.clone()).await;
                Ok(())
            }
        }
    }

    /// Handles local device events and propagates authoritative updates to followers.
    ///
    /// Lock and unlock events are broadcast to active followers. Timer events prune stale
    /// follower sessions that have not sent recent heartbeats.
    pub async fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        match event {
            DeviceEvent::ManualLock { user_id } => {
                let message = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.broadcast_to_active_followers(message).await;
            }
            DeviceEvent::ManualUnlock { user_id, user_key } => {
                let message = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: UserKey::from_bytes(user_key),
                    },
                };
                self.broadcast_to_active_followers(message).await;
            }
            DeviceEvent::Timer => {
                self.follower_sessions
                    .prune_stale(get_current_timestamp(), FOLLOWER_STALE_AFTER);
            }
        }

        Ok(())
    }

    async fn send_message(&self, message: LeaderMessage, recipient: Endpoint) {
        if let Err(error) = self.ipc_client.send_typed(message, recipient).await {
            tracing::error!(?error, "Failed to send shared unlock IPC message");
        }
    }
}

fn get_current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_millis() as u64
    }
}
