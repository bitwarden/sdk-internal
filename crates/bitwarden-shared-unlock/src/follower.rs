use std::{ops::Add, sync::Arc};

use bitwarden_error::bitwarden_error;
use bitwarden_ipc::{Endpoint, IpcClient, IpcClientExt, SubscribeError, TypedIncomingMessage};
use bitwarden_threading::cancellation_token;
use thiserror::Error;

use crate::{DeviceEvent, FollowerMessage, LeaderMessage, LockState, drivers::SharedUnlockDriver};

/// Error type for failure to start the shared unlock follower.
#[bitwarden_error(basic)]
#[derive(Debug, Error)]
#[error("Could not start shared unlock follower: {0}")]
pub struct FollowerStartError(#[from] SubscribeError);

/// Tracks local state and follows authoritative lock updates from a leader.
pub struct Follower<L: SharedUnlockDriver>(Arc<InnerFollower<L>>);

impl<L: SharedUnlockDriver> Clone for Follower<L> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Inner implementation of the shared unlock follower, containing the actual state and logic. The
/// outer `Follower` struct is a thin wrapper around an `Arc` to allow for shared ownership across
/// async tasks.
pub struct InnerFollower<D: SharedUnlockDriver> {
    driver: D,
    ipc_client: Arc<dyn IpcClient>,
}

impl<L: SharedUnlockDriver + Send + Sync + 'static> Follower<L> {
    /// Creates a follower instance and starts sessions for all currently known users.
    ///
    /// During startup, a `StartSession` message is sent per user so the leader can reconcile
    /// initial lock state.
    pub fn create(driver: L, ipc_client: Arc<dyn IpcClient>) -> Self {
        Self(Arc::new(InnerFollower { driver, ipc_client }))
    }

    async fn start_sessions(&self) {
        let users: Vec<bitwarden_core::UserId> = self.0.driver.list_users().await;
        let leader = self
            .0
            .driver
            .discover_leader()
            .await
            .expect("leader discovery should return a leader");

        for user_id in users {
            let lock_state = self.0.driver.get_user_lock_state(user_id).await;
            let message = FollowerMessage::StartSession {
                user_id,
                lock_state,
            };
            self.send_message(message, leader.clone()).await;
        }
    }

    /// Starts background tasks for IPC message handling and heartbeat timers.
    pub async fn start(
        &self,
        cancellation_token: Option<cancellation_token::CancellationToken>,
    ) -> Result<(), FollowerStartError> {
        let cancellation_token = cancellation_token.unwrap_or_default();
        let mut subscription = self.0.ipc_client.subscribe_typed::<LeaderMessage>().await?;
        let follower = self.clone();

        let cancellation_token_clone = cancellation_token.clone();
        let future = async move {
            loop {
                let result = subscription
                    .receive(Some(cancellation_token_clone.clone()))
                    .await;
                match result {
                    Ok(message) => {
                        if let Err(error) = follower.receive_message(message).await {
                            tracing::error!(
                                ?error,
                                "Failed to handle shared unlock follower message"
                            );
                        }
                    }
                    Err(bitwarden_ipc::TypedReceiveError::Cancelled) => {
                        tracing::info!("Shared unlock follower stopped by cancellation");
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
        let follower = self.clone();
        let timer_future = async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock follower timer cancelled");
                        break;
                    }
                    _ = bitwarden_threading::time::sleep(crate::HEARTBEAT_INTERVAL) => {
                        if let Some(leader) = follower.0.driver.discover_leader().await {
                            // For all users that are logged in, send a heartbeat message to the leader.
                            for user_id in follower.0.driver.list_users().await {
                                let message = FollowerMessage::HeartBeat { user_id };
                                follower.send_message(message, leader.clone()).await;
                            }
                        }
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(timer_future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(timer_future);

        self.start_sessions().await;
        Ok(())
    }

    /// Handles an authoritative message from the leader.
    ///
    /// Lock state updates overwrite local state to keep follower and leader in sync. Heartbeat
    /// responses are forwarded to the heartbeat response handler.
    pub async fn receive_message(
        &self,
        incoming_message: TypedIncomingMessage<LeaderMessage>,
    ) -> Result<(), ()> {
        let message = incoming_message.payload;
        match message {
            LeaderMessage::LockStateUpdate {
                user_id,
                lock_state,
            } => {
                // The leader is the authoritative state source for the follow, and it should
                // always overwrite the local state of the follower.
                let current_state = self.0.driver.get_user_lock_state(user_id).await;

                match (current_state, lock_state) {
                    (LockState::Unlocked { .. }, LockState::Locked) => {
                        // If the user is currently unlocked and it receives an authoritative lock
                        // state update from the leader that is Locked, then
                        // it should follow, and lock the local state.
                        self.0.driver.lock_user(user_id).await?;
                    }
                    (LockState::Locked, LockState::Unlocked { user_key }) => {
                        // If the user is currently locked and it receives an authoritative lock
                        // state update from the leader that is Unlocked,
                        // then it should follow, and unlock the local state.
                        self.0.driver.unlock_user(user_id, user_key).await?;
                    }
                    (LockState::Locked, LockState::Locked)
                    | (LockState::Unlocked { .. }, LockState::Unlocked { .. }) => {
                        // If both the current state and the received lock state are the same, then
                        // do nothing, as they are already in sync.
                    }
                }
            }
            LeaderMessage::HeartBeat { user_id } => {
                self.0
                    .driver
                    .suppress_vault_timeout(
                        user_id,
                        crate::HEARTBEAT_INTERVAL.add(crate::VAULT_TIMEOUT_GRACE_PERIOD),
                    )
                    .await;
            }
        }

        Ok(())
    }

    /// Handles local device events and forwards them to the discovered leader.
    ///
    /// Manual lock/unlock events are sent as lock state updates. Timer events send per-user
    /// heartbeats to keep the shared session active.
    pub async fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        let leader = self.0.driver.discover_leader().await.ok_or(())?;

        match event {
            DeviceEvent::ManualLock { user_id } => {
                let message = FollowerMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Locked,
                };
                self.send_message(message, leader).await;
            }
            DeviceEvent::ManualUnlock {
                user_id,
                ref user_key,
            } => {
                let message = FollowerMessage::LockStateUpdate {
                    user_id,
                    lock_state: LockState::Unlocked {
                        user_key: super::UserKey::from_bytes(user_key.to_owned()),
                    },
                };
                self.send_message(message, leader).await;
            }
        }

        Ok(())
    }

    async fn send_message(&self, message: FollowerMessage, recipient: Endpoint) {
        if let Err(error) = self.0.ipc_client.send_typed(message, recipient).await {
            tracing::error!(?error, "Failed to send shared unlock IPC message");
        }
    }
}
