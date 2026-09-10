//! The single participant type of the shared unlock protocol.
//!
//! Every client runs exactly one [`SharedUnlockPeer`]. A peer syncs its lock state to the peer it
//! recognizes as its leader and to the peers that sync to it.
//!
//! A web peer is scoped to the origin it was validated against: it is only ever told about the
//! users whose vault URL is that origin, in either direction.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_core::UserId;
use bitwarden_error::bitwarden_error;
use bitwarden_ipc::{
    Endpoint, IpcClient, IpcClientExt, RequestError, Source, SubscribeError, TypedIncomingMessage,
};
use bitwarden_threading::{cancellation_token, time::sleep};
use thiserror::Error;
use tracing::warn;

use crate::{
    DeviceEvent, LockState, SharedUnlockSync, TimestampedLockState,
    active_peers::{ActivePeerTracker, SyncTarget},
    drivers::SharedUnlockDriver,
    timing::{SharedUnlockTiming, now_millis},
};

/// Error type for failure to start a shared unlock peer.
#[bitwarden_error(basic)]
#[derive(Debug, Error)]
#[error("Could not start shared unlock peer: {0}")]
pub struct PeerStartError(#[from] SubscribeError);

/// One participant in the shared unlock protocol.
pub struct SharedUnlockPeer<D: SharedUnlockDriver>(Arc<InnerPeer<D>>);

impl<D: SharedUnlockDriver> Clone for SharedUnlockPeer<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Inner implementation of the peer, containing the actual state and logic. The outer
/// `SharedUnlockPeer` is a thin wrapper around an `Arc` to allow for shared ownership across async
/// tasks.
struct InnerPeer<D: SharedUnlockDriver> {
    driver: D,
    ipc_client: Arc<dyn IpcClient>,
    /// This device's view of each user's lock state.
    states: Mutex<HashMap<UserId, TimestampedLockState>>,
    active_peers: ActivePeerTracker,
    timing: SharedUnlockTiming,
}

impl<D: SharedUnlockDriver + Send + Sync + 'static> SharedUnlockPeer<D> {
    /// Creates a peer. Nothing is sent until [`SharedUnlockPeer::start`] is called.
    pub fn create(driver: D, ipc_client: Arc<dyn IpcClient>) -> Self {
        Self::create_with_timing(driver, ipc_client, SharedUnlockTiming::default())
    }

    /// Creates a peer that syncs on the given timings rather than the production ones, so tests do
    /// not have to wait out a 5s interval. Compiled only for tests and under `test-support`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_for_test(
        driver: D,
        ipc_client: Arc<dyn IpcClient>,
        sync_interval: Duration,
        vault_timeout_grace_period: Duration,
        peer_stale_after: Duration,
    ) -> Self {
        Self::create_with_timing(
            driver,
            ipc_client,
            SharedUnlockTiming {
                sync_interval,
                vault_timeout_grace_period,
                peer_stale_after,
            },
        )
    }

    fn create_with_timing(
        driver: D,
        ipc_client: Arc<dyn IpcClient>,
        timing: SharedUnlockTiming,
    ) -> Self {
        Self(Arc::new(InnerPeer {
            driver,
            ipc_client,
            states: Mutex::new(HashMap::new()),
            active_peers: ActivePeerTracker::default(),
            timing,
        }))
    }

    /// Starts the receive loop and the sync timer, then announces this peer's state once so it does
    /// not have to wait a full interval to be discovered.
    pub async fn start(
        &self,
        cancellation_token: Option<cancellation_token::CancellationToken>,
    ) -> Result<(), PeerStartError> {
        let cancellation_token = cancellation_token.unwrap_or_default();
        let mut subscription = self
            .0
            .ipc_client
            .subscribe_typed::<SharedUnlockSync>()
            .await?;

        let peer = self.clone();
        let receive_token = cancellation_token.clone();
        let receive_loop = async move {
            loop {
                match subscription.receive(Some(receive_token.clone())).await {
                    Ok(message) => {
                        if let Err(error) = peer.receive_message(message).await {
                            tracing::error!(?error, "Failed to handle shared unlock sync");
                        }
                    }
                    Err(bitwarden_ipc::TypedReceiveError::Cancelled) => {
                        tracing::info!("Shared unlock peer stopped by cancellation");
                        break;
                    }
                    // This is required because otherwise the browser may freeze in this loop
                    Err(bitwarden_ipc::TypedReceiveError::Channel(
                        tokio::sync::broadcast::error::RecvError::Closed,
                    )) => {
                        tracing::info!("Transport channel closed. Waiting for it to open");
                        sleep(Duration::from_secs(1)).await;
                    }
                    Err(error) => {
                        tracing::error!(?error, "Failed to receive shared unlock IPC message");
                    }
                }
            }
        };

        spawn(receive_loop);

        let peer = self.clone();
        let timer_token = cancellation_token.clone();
        let timing = self.0.timing;
        let timer_loop = async move {
            loop {
                tokio::select! {
                    _ = timer_token.cancelled() => {
                        tracing::debug!("Shared unlock peer timer cancelled");
                        break;
                    }
                    _ = sleep(timing.sync_interval) => {
                        peer.0.active_peers.prune_stale(timing.peer_stale_after);
                        peer.sync_all_users().await;
                    }
                }
            }
        };

        spawn(timer_loop);

        self.sync_all_users().await;
        Ok(())
    }

    /// Handles a sync from another peer.
    pub async fn receive_message(
        &self,
        incoming_message: TypedIncomingMessage<SharedUnlockSync>,
    ) -> Result<(), ()> {
        let source = incoming_message.source;
        let SharedUnlockSync { user_id, state } = incoming_message.payload;

        // Validate the origin of web sources against the user's vault URL
        if let Source::Web { origin, .. } = &source {
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

        if !self.0.driver.list_users().await.contains(&user_id) {
            tracing::debug!(
                %user_id,
                "Ignoring shared unlock sync for a user this device has no account for"
            );
            return Ok(());
        }

        let target = SyncTarget::from_source(&source);
        let from_leader = self.0.driver.discover_leader().await.as_ref() == Some(&target.endpoint);
        if from_leader {
            // Suppressed before applying, so a lock or unlock that takes seconds to settle cannot
            // let the previously granted suppression lapse in the meantime.
            self.0
                .driver
                .suppress_vault_timeout(
                    user_id,
                    self.0.timing.sync_interval + self.0.timing.vault_timeout_grace_period,
                )
                .await;
        }

        let first_contact = self.0.active_peers.upsert(&target);
        self.apply_remote_state(user_id, state).await?;

        if first_contact {
            self.sync_all_users_to(&target).await;
        }

        Ok(())
    }

    /// Records a lock state change made on this device and syncs it to every peer immediately.
    pub async fn handle_device_event(&self, event: DeviceEvent) -> Result<(), ()> {
        let (user_id, lock_state) = match &event {
            DeviceEvent::ManualLock { user_id } => (*user_id, LockState::Locked),
            DeviceEvent::ManualUnlock { user_id, user_key } => (
                *user_id,
                LockState::Unlocked {
                    user_key: user_key.to_owned(),
                },
            ),
        };

        tracing::debug!(
            %user_id,
            lock_state = lock_state.describe(),
            "Shared unlock device event reported by this client"
        );

        self.record_local_state(user_id, lock_state);
        self.sync_user(user_id).await;
        Ok(())
    }

    /// Applies a peer's state if it is newer than what this device has recorded.
    async fn apply_remote_state(
        &self,
        user_id: UserId,
        remote: TimestampedLockState,
    ) -> Result<(), ()> {
        if !remote.supersedes(self.recorded_state(user_id).as_ref()) {
            return Ok(());
        }

        // Compared against what this peer *advertises*, not against what it has recorded, so the
        // two agree: an unobserved user is advertised as locked, and must therefore be
        // treated as locked here too. Comparing against the raw record instead would make
        // an incoming `Locked` "differ" from an unobserved user and re-lock an
        // already-locked device on every restart — which a client that restarts on lock
        // turns into an endless restart loop.
        let differs = remote.lock_state != self.advertised_state(user_id).lock_state;
        if differs {
            tracing::debug!(
                %user_id,
                lock_state = remote.lock_state.describe(),
                changed_at = remote.changed_at,
                "Applying a peer's lock state through the driver"
            );

            match &remote.lock_state {
                LockState::Locked => self
                    .0
                    .driver
                    .lock_user(user_id)
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to lock user"))?,
                LockState::Unlocked { user_key } => self
                    .0
                    .driver
                    .unlock_user(user_id, user_key.to_owned())
                    .await
                    .inspect_err(|_| warn!(%user_id, "Failed to unlock user"))?,
            }
        }

        self.record_remote_state(user_id, remote);
        Ok(())
    }

    /// Sends this peer's state for every logged-in user to every peer it syncs with.
    async fn sync_all_users(&self) {
        for user_id in self.0.driver.list_users().await {
            self.sync_user(user_id).await;
        }
    }

    async fn sync_user(&self, user_id: UserId) {
        for target in self.sync_targets().await {
            self.sync_user_to(user_id, &target).await;
        }
    }

    /// Sends this peer's state for every logged-in user to one specific peer.
    async fn sync_all_users_to(&self, target: &SyncTarget) {
        for user_id in self.0.driver.list_users().await {
            self.sync_user_to(user_id, target).await;
        }
    }

    async fn sync_user_to(&self, user_id: UserId, target: &SyncTarget) {
        if !self.may_sync_user_to(user_id, target).await {
            return;
        }

        let message = SharedUnlockSync {
            user_id,
            state: self.advertised_state(user_id),
        };
        self.send_message(message, target.endpoint.clone()).await;
    }

    /// Whether a user's state may be sent to a peer.
    ///
    /// A web peer is entitled only to the users whose vault URL is the origin it was validated
    /// against — the same rule [`SharedUnlockPeer::receive_message`] applies to incoming syncs,
    /// applied outbound so a page served by one vault is never handed another vault's key material.
    /// A web peer with no recorded origin fails closed.
    async fn may_sync_user_to(&self, user_id: UserId, target: &SyncTarget) -> bool {
        if !matches!(target.endpoint, Endpoint::Web { .. }) {
            return true;
        }

        let Some(origin) = target.origin.as_deref() else {
            warn!(
                ?target,
                "Web peer has no validated origin, not syncing to it"
            );
            return false;
        };

        match self.0.driver.get_vault_url(user_id).await {
            Some(user_vault_url) if user_vault_url == origin => true,
            Some(user_vault_url) => {
                warn!(%origin, %user_vault_url, %user_id, "Web peer's origin does not match the user's vault URL, not syncing that user to it");
                false
            }
            None => {
                warn!(%origin, %user_id, "No vault URL found for user, not syncing that user to a web peer");
                false
            }
        }
    }

    /// This peer's leader, if it has one, plus every peer that syncs to it.
    async fn sync_targets(&self) -> Vec<SyncTarget> {
        let mut targets = self.0.active_peers.targets();
        if let Some(leader) = self.0.driver.discover_leader().await
            && !targets.iter().any(|target| target.endpoint == leader)
        {
            // A leader is discovered rather than validated, so it carries no origin. In practice it
            // is never a web endpoint; if it ever were, `may_sync_user_to` fails it closed.
            targets.push(SyncTarget::without_origin(leader));
        }
        targets
    }

    async fn send_message(&self, message: SharedUnlockSync, recipient: Endpoint) {
        tracing::debug!(
            user_id = %message.user_id,
            lock_state = message.state.lock_state.describe(),
            changed_at = message.state.changed_at,
            ?recipient,
            "Sending a shared unlock sync"
        );

        if let Err(error) = self
            .0
            .ipc_client
            .send_typed(message, recipient.clone())
            .await
        {
            match error {
                RequestError::Unreachable => {
                    // Expected whenever a peer is not running — a device with no desktop app syncs
                    // into the void on every tick — so this stays at debug to avoid a steady stream
                    // of warnings for a normal configuration.
                    tracing::debug!(
                        ?recipient,
                        "Shared unlock peer unreachable; sync not delivered"
                    );
                }
                RequestError::Timeout(_) => {
                    tracing::warn!(?error, "Timeout sending shared unlock sync");
                }
                _ => {
                    tracing::error!(?error, "Failed to send shared unlock IPC message");
                }
            }
        }
    }

    // --- Lock state -----------------------------------------------------------------------------

    /// The date this peer has recorded for a user, for tests that assert two peers converged on one
    /// date and not merely on one state. Compiled only for tests and under `test-support`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn recorded_changed_at(&self, user_id: UserId) -> Option<u64> {
        self.recorded_state(user_id).map(|state| state.changed_at)
    }

    fn recorded_state(&self, user_id: UserId) -> Option<TimestampedLockState> {
        self.0
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&user_id)
            .cloned()
    }

    /// The state to advertise for a user: the recorded one, or a presence marker.
    fn advertised_state(&self, user_id: UserId) -> TimestampedLockState {
        self.recorded_state(user_id).unwrap_or_default()
    }

    /// Records a state reported by a peer, if it still supersedes what is recorded.
    fn record_remote_state(&self, user_id: UserId, state: TimestampedLockState) {
        let mut states = self
            .0
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if state.supersedes(states.get(&user_id)) {
            states.insert(user_id, state);
        }
    }

    /// Records a change made on this device.
    fn record_local_state(&self, user_id: UserId, lock_state: LockState) {
        let mut states = self
            .0
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let changed_at = states
            .get(&user_id)
            .map_or(0, |recorded| recorded.changed_at.saturating_add(1))
            .max(now_millis());

        states.insert(
            user_id,
            TimestampedLockState {
                lock_state,
                changed_at,
            },
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}

#[cfg(target_arch = "wasm32")]
fn spawn(future: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(future);
}
