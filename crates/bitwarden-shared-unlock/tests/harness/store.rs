//! The in-memory lock state each simulated device exposes as its `SharedUnlockDriver`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::Endpoint;
use bitwarden_shared_unlock::{LockState, SharedUnlockDriver};
use bitwarden_threading::time::sleep;

use super::logs::{TopologyId, emit_log, kind};

#[derive(Clone, Copy, Debug)]
pub(crate) struct LockDelays {
    pub(crate) lock: Duration,
    pub(crate) unlock: Duration,
}

/// Whether a lock/unlock came from the protocol or was driven by the test as a local UI action.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LockOrigin {
    Protocol,
    Local,
}

impl LockOrigin {
    fn label(&self) -> &'static str {
        match self {
            LockOrigin::Protocol => "protocol",
            LockOrigin::Local => "local",
        }
    }
}

type ProtocolLockHook = Box<dyn Fn(UserId) + Send + Sync>;

/// In-memory lock state implementing [`SharedUnlockDriver`].
///
/// Lock and unlock flip the state *immediately* and then await a settling tail. Because a peer's
/// receive loop awaits the driver inline, that tail stalls all IPC processing on that device for
/// its duration — which is the behaviour under test.
///
/// A user the device has no account for is not merely reported as locked: `lock_user` /
/// `unlock_user` reject it, mirroring a client asked to operate on a user it does not know. That
/// keeps "user not shared with this device" from silently becoming "shared after the first unlock".
#[derive(Clone)]
pub(crate) struct LockStateStore(Arc<StoreInner>);

struct StoreInner {
    device_name: String,
    /// What `discover_leader` reports: the endpoint of the device declared above this one.
    leader: Option<Endpoint>,
    /// Absent means no account for that user; `None` means locked.
    states: Mutex<HashMap<UserId, Option<SymmetricCryptoKey>>>,
    in_flight: Mutex<HashMap<UserId, usize>>,
    delays: LockDelays,
    vault_url: Option<String>,
    topology: TopologyId,
    /// Called after a protocol-driven lock has fully settled. Used to implement device quirks.
    on_protocol_lock_settled: Mutex<Option<ProtocolLockHook>>,
}

impl LockStateStore {
    pub(super) fn new(
        device_name: &str,
        leader: Option<Endpoint>,
        users: &[UserId],
        delays: LockDelays,
        vault_url: Option<String>,
        topology: TopologyId,
    ) -> Self {
        Self(Arc::new(StoreInner {
            device_name: device_name.to_owned(),
            leader,
            states: Mutex::new(users.iter().map(|user| (*user, None)).collect()),
            in_flight: Mutex::new(HashMap::new()),
            delays,
            vault_url,
            topology,
            on_protocol_lock_settled: Mutex::new(None),
        }))
    }

    pub(super) fn set_protocol_lock_hook(&self, hook: ProtocolLockHook) {
        *self
            .0
            .on_protocol_lock_settled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Synchronous read, for assertions and convergence polling. A user this device has no
    /// account for reads as locked, same as one it has locked.
    pub(crate) fn peek(&self, user_id: UserId) -> LockState {
        match self.lock_states().get(&user_id).cloned().flatten() {
            Some(user_key) => LockState::Unlocked { user_key },
            None => LockState::Locked,
        }
    }

    pub(crate) fn knows(&self, user_id: UserId) -> bool {
        self.lock_states().contains_key(&user_id)
    }

    /// Applies a lock (`None`) or unlock locally, as if the UI had done it.
    pub(super) async fn apply_local(&self, user_id: UserId, key: Option<SymmetricCryptoKey>) {
        let _ = self.apply(user_id, key, LockOrigin::Local).await;
    }

    async fn apply(
        &self,
        user_id: UserId,
        key: Option<SymmetricCryptoKey>,
        origin: LockOrigin,
    ) -> Result<(), ()> {
        if !self.knows(user_id) {
            emit_log(
                self.0.topology,
                &self.0.device_name,
                kind::NOTE,
                Some(user_id),
                &format!(
                    "rejected {} operation: no account for this user",
                    origin.label()
                ),
            );
            return Err(());
        }

        let unlocking = key.is_some();
        {
            let mut in_flight = self
                .0
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let outstanding = in_flight.entry(user_id).or_insert(0);
            if *outstanding > 0 {
                emit_log(
                    self.0.topology,
                    &self.0.device_name,
                    kind::OVERLAP,
                    Some(user_id),
                    &format!(
                        "{} started while {outstanding} operation(s) still settling",
                        if unlocking { "unlock" } else { "lock" }
                    ),
                );
            }
            *outstanding += 1;
        }

        emit_log(
            self.0.topology,
            &self.0.device_name,
            if unlocking {
                kind::UNLOCK_START
            } else {
                kind::LOCK_START
            },
            Some(user_id),
            origin.label(),
        );
        self.lock_states().insert(user_id, key);

        sleep(if unlocking {
            self.0.delays.unlock
        } else {
            self.0.delays.lock
        })
        .await;

        {
            let mut in_flight = self
                .0
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(outstanding) = in_flight.get_mut(&user_id) {
                *outstanding = outstanding.saturating_sub(1);
            }
        }
        emit_log(
            self.0.topology,
            &self.0.device_name,
            if unlocking {
                kind::UNLOCK_END
            } else {
                kind::LOCK_END
            },
            Some(user_id),
            origin.label(),
        );
        Ok(())
    }

    fn lock_states(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<UserId, Option<SymmetricCryptoKey>>> {
        self.0
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait::async_trait]
impl SharedUnlockDriver for LockStateStore {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.apply(user_id, None, LockOrigin::Protocol).await?;

        let hook = self
            .0
            .on_protocol_lock_settled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(hook) = hook.as_ref() {
            hook(user_id);
        }
        Ok(())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: SymmetricCryptoKey) -> Result<(), ()> {
        self.apply(user_id, Some(user_key), LockOrigin::Protocol)
            .await
    }

    async fn list_users(&self) -> Vec<UserId> {
        self.lock_states().keys().copied().collect()
    }

    async fn get_vault_url(&self, _user_id: UserId) -> Option<String> {
        self.0.vault_url.clone()
    }

    async fn suppress_vault_timeout(&self, user_id: UserId, suppression_duration: Duration) {
        // Deliberately a no-op beyond recording it. The record doubles as a liveness signal: it
        // stops arriving when a peer's receive loop has stopped handling its leader's
        // syncs.
        emit_log(
            self.0.topology,
            &self.0.device_name,
            kind::SUPPRESS_TIMEOUT,
            Some(user_id),
            &format!("{}ms", suppression_duration.as_millis()),
        );
    }

    async fn discover_leader(&self) -> Option<Endpoint> {
        self.0.leader.clone()
    }
}
