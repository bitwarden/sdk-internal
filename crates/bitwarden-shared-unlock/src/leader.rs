use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_error::bitwarden_error;
use bitwarden_ipc::{Endpoint, IpcClient, IpcClientExt, SubscribeError, TypedIncomingMessage};
use bitwarden_threading::cancellation_token;
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    DeviceEvent, FollowerMessage, LeaderMessage, LockState, UserKey, drivers::SharedUnlockDriver,
};

const FOLLOWER_STALE_AFTER: Duration = Duration::from_secs(30);

/// Error type for failure to start the shared unlock leader.
#[bitwarden_error(basic)]
#[derive(Debug, Error)]
#[error("Could not start shared unlock leader: {0}")]
pub struct LeaderStartError(#[from] SubscribeError);

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

    fn upsert(&self, endpoint: bitwarden_ipc::Endpoint) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if !sessions.contains_key(&endpoint) {
            info!("Shared-Unlock client connected {:?}", endpoint);
        }

        sessions.insert(
            endpoint,
            FollowerSession {
                last_seen_at: get_current_timestamp(),
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

    fn prune_stale(&self, stale_after: Duration) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = get_current_timestamp();
        let stale_after_millis = stale_after.as_millis() as u64;
        for (endpoint, session) in sessions.iter() {
            if now.saturating_sub(session.last_seen_at) > stale_after_millis {
                info!("Shared-Unlock client {:?} disconnected", endpoint);
            }
        }
        sessions
            .retain(|_, session| now.saturating_sub(session.last_seen_at) <= stale_after_millis);
    }
}

/// Coordinates shared unlock state as the authoritative endpoint for followers.
pub struct Leader<L: SharedUnlockDriver>(Arc<InnerLeader<L>>);

impl<L: SharedUnlockDriver> Clone for Leader<L> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Inner implementation of the shared unlock leader, containing the actual state and logic. The
/// outer `Leader` struct is a thin wrapper around an `Arc` to allow for shared ownership across
/// async tasks.
struct InnerLeader<D: SharedUnlockDriver> {
    driver: D,
    follower_sessions: FollowerSessions,
    ipc_client: Arc<dyn IpcClient>,
}

impl<D: SharedUnlockDriver + Send + Sync + 'static> Leader<D> {
    /// Creates a leader instance for the shared unlock protocol.
    pub fn create(lock_system: D, ipc_client: Arc<dyn IpcClient>) -> Self {
        Self(Arc::new(InnerLeader {
            driver: lock_system,
            follower_sessions: FollowerSessions::new(),
            ipc_client,
        }))
    }

    /// Starts background processing for incoming follower messages.
    pub async fn start(
        &self,
        cancellation_token: Option<cancellation_token::CancellationToken>,
    ) -> Result<(), LeaderStartError> {
        let cancellation_token = cancellation_token.unwrap_or_default();
        let mut subscription = self
            .0
            .ipc_client
            .subscribe_typed::<FollowerMessage>()
            .await?;
        let leader = self.clone();

        let cancellation_token_clone = cancellation_token.clone();
        let future = async move {
            loop {
                let result = subscription
                    .receive(Some(cancellation_token_clone.clone()))
                    .await;
                match result {
                    Ok(message) => {
                        if let Err(error) = leader.receive_message(message).await {
                            tracing::error!(
                                ?error,
                                "Failed to handle shared unlock leader message"
                            );
                        }
                    }
                    Err(bitwarden_ipc::TypedReceiveError::Cancelled) => {
                        tracing::info!("Shared unlock leader stopped by cancellation");
                        break;
                    }
                    Err(error) => {
                        tracing::error!(?error, "Failed to receive shared unlock IPC message");
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);

        let cancellation_token = cancellation_token.clone();
        let leader = self.clone();
        let timer_future = async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock follower timer cancelled");
                        break;
                    }
                    _ = bitwarden_threading::time::sleep(crate::HEARTBEAT_INTERVAL) => {
                        leader.0
                            .follower_sessions
                            .prune_stale(FOLLOWER_STALE_AFTER);
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(timer_future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(timer_future);

        Ok(())
    }

    async fn broadcast_to_active_followers(&self, message: LeaderMessage) {
        let endpoints = self.0.follower_sessions.active_endpoints();
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
        let endpoint: bitwarden_ipc::Endpoint = sender.clone().into();

        // Validate the origin of web sources against the user's vault URL
        if let bitwarden_ipc::Source::Web { origin, .. } = &sender {
            let user_id = message.user_id();
            match self.0.driver.get_vault_url(user_id).await {
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
                self.0.follower_sessions.upsert(endpoint.clone());

                let self_lock_state = self.0.driver.get_user_lock_state(user_id).await;
                if self_lock_state == LockState::Locked {
                    return Ok(());
                }

                self.0
                    .driver
                    .lock_user(user_id)
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to lock user"))?;
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
                self.0.follower_sessions.upsert(endpoint.clone());

                let self_lock_state = self.0.driver.get_user_lock_state(user_id).await;
                if let LockState::Unlocked { .. } = self_lock_state {
                    return Ok(());
                }

                self.0
                    .driver
                    .unlock_user(user_id, user_key.clone())
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to unlock user"))?;
                Ok(())
            }
            FollowerMessage::StartSession {
                user_id,
                lock_state,
            } => {
                self.0.follower_sessions.upsert(endpoint.clone());
                let self_lock_state = self.0.driver.get_user_lock_state(user_id).await;

                match (lock_state, self_lock_state.clone()) {
                    (LockState::Unlocked { user_key }, LockState::Locked) => {
                        self.0
                            .driver
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
                self.0.follower_sessions.upsert(endpoint.clone());

                // Echo back the heartbeat to confirm liveness
                let response = LeaderMessage::HeartBeat { user_id };
                self.send_message(response, endpoint.clone()).await;

                let lock_state = self.0.driver.get_user_lock_state(user_id).await;
                // Ensure that if somehow the lockstate is desynced, it syncs again
                let authoritative_lockstate_update = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state,
                };
                self.send_message(authoritative_lockstate_update, endpoint.clone())
                    .await;
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
            DeviceEvent::ManualUnlock {
                user_id,
                ref user_key,
            } => {
                let message = LeaderMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: UserKey::from_bytes(user_key.to_owned()),
                    },
                };
                self.broadcast_to_active_followers(message).await;
            }
        }

        Ok(())
    }

    async fn send_message(&self, message: LeaderMessage, recipient: Endpoint) {
        if let Err(error) = self.0.ipc_client.send_typed(message, recipient).await {
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
