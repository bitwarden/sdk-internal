//! A single simulated client process, running one real `SharedUnlockPeer`.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::{
    Endpoint, IpcClient, IpcClientImpl, NoiseCryptoProvider, NoiseCryptoProviderState, Source,
};
use bitwarden_shared_unlock::{DeviceEvent, SharedUnlockPeer};
use bitwarden_threading::{cancellation_token::CancellationToken, time::sleep};

use super::{
    FAST_DELAYS, Timing,
    client_type::ClientType,
    in_memory_ipc_transport::{InMemoryIpcTransport, TransportBackend},
    logs::{
        REPLAYED_MANUAL_LOCK, TEST_MANUAL_LOCK, TEST_MANUAL_UNLOCK, TopologyId, emit_log, kind,
    },
    store::{LockDelays, LockStateStore},
};

/// Behaviours real clients exhibit that a plain protocol test does not model.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DeviceQuirks {
    /// After a protocol-driven lock settles, report it back into this device's own peer as a
    /// `ManualLock`. Real clients drive shared unlock off their lock-state observable, so a lock
    /// the protocol applied surfaces again as a local lock event.
    pub(crate) replay_incoming_lock_as_manual_lock: bool,
    /// After a protocol-driven lock settles, reload the process. Models the browser extension,
    /// whose background context restarts on lock.
    pub(crate) reload_after_lock: Option<Duration>,
}

pub(crate) struct DeviceOptions {
    pub(crate) client_type: ClientType,
    /// Users this device has an account for. Anything outside this list is unknown to it.
    pub(crate) users: Vec<UserId>,
    pub(crate) delays: LockDelays,
    /// Required for a web client: its leader validates the web origin against this.
    pub(crate) vault_url: Option<String>,
    pub(crate) quirks: DeviceQuirks,
    /// The device this one syncs up to. Must be `None` exactly when the client type has no leader.
    pub(crate) leader: Option<SimulatedDevice>,
}

impl DeviceOptions {
    pub(crate) fn new(client_type: ClientType, users: &[UserId]) -> Self {
        Self {
            client_type,
            users: users.to_vec(),
            delays: FAST_DELAYS,
            vault_url: None,
            quirks: DeviceQuirks::default(),
            leader: None,
        }
    }

    pub(crate) fn following(mut self, leader: &SimulatedDevice) -> Self {
        self.leader = Some(leader.clone());
        self
    }

    pub(crate) fn with_vault_url(mut self, vault_url: &str) -> Self {
        self.vault_url = Some(vault_url.to_owned());
        self
    }

    pub(crate) fn with_delays(mut self, delays: LockDelays) -> Self {
        self.delays = delays;
        self
    }

    pub(crate) fn with_quirks(mut self, quirks: DeviceQuirks) -> Self {
        self.quirks = quirks;
        self
    }
}

/// A single simulated client process, running exactly one [`SharedUnlockPeer`] — including a
/// browser extension, which serves the web vault and syncs up to the desktop app with that one
/// peer.
///
/// Declaration-time identity is stable for the lifetime of the topology; the runtime is rebuilt by
/// [`SimulatedDevice::process_reload`], so tests keep holding the same handle across a restart.
#[derive(Clone)]
pub(crate) struct SimulatedDevice(pub(super) Arc<DeviceInner>);

pub(super) struct DeviceInner {
    name: String,
    endpoint: Endpoint,
    source: Source,
    users: Vec<UserId>,
    delays: LockDelays,
    vault_url: Option<String>,
    quirks: DeviceQuirks,
    /// The endpoint this device's driver reports from `discover_leader`, or `None` at the top of
    /// the hierarchy. Taken from the declared leader rather than computed, so each of two browsers
    /// serves its own web clients.
    leader: Option<Endpoint>,
    timing: Timing,
    transport: Arc<InMemoryIpcTransport>,
    topology: TopologyId,
    runtime: Mutex<Option<DeviceRuntime>>,
    /// Depth from the top of the hierarchy, for start ordering.
    depth: AtomicUsize,
}

struct DeviceRuntime {
    store: LockStateStore,
    peer: SharedUnlockPeer<LockStateStore>,
    token: CancellationToken,
}

impl SimulatedDevice {
    /// Builds a device from its declaration. Lives here rather than in the topology so
    /// `DeviceInner` stays private to this module.
    pub(super) fn declare(
        name: &str,
        options: DeviceOptions,
        instance: i32,
        timing: Timing,
        transport: Arc<InMemoryIpcTransport>,
        topology: TopologyId,
        depth: usize,
    ) -> Self {
        Self(Arc::new(DeviceInner {
            name: name.to_owned(),
            endpoint: options.client_type.endpoint(instance, name),
            source: options
                .client_type
                .source(instance, name, options.vault_url.as_deref()),
            leader: options
                .leader
                .as_ref()
                .map(|leader| leader.endpoint().clone()),
            users: options.users,
            delays: options.delays,
            vault_url: options.vault_url,
            quirks: options.quirks,
            timing,
            transport,
            topology,
            runtime: Mutex::new(None),
            depth: AtomicUsize::new(depth),
        }))
    }

    /// Where this device sits in the hierarchy, for start ordering.
    pub(super) fn depth(&self) -> usize {
        self.0.depth.load(Ordering::SeqCst)
    }

    /// The endpoint this device is addressed at, which the topology validates against its declared
    /// leader.
    pub(super) fn endpoint(&self) -> &Endpoint {
        &self.0.endpoint
    }

    pub(crate) fn name(&self) -> &str {
        &self.0.name
    }

    /// The driver store of the currently booted process.
    pub(crate) fn store(&self) -> LockStateStore {
        self.lock_runtime()
            .as_ref()
            .expect("Device should be booted")
            .store
            .clone()
    }

    /// The date this device's peer has recorded for a user, so a test can assert two peers
    /// converged on one date rather than merely on one state.
    pub(crate) fn recorded_date(&self, user_id: UserId) -> Option<u64> {
        self.lock_runtime()
            .as_ref()
            .and_then(|runtime| runtime.peer.recorded_changed_at(user_id))
    }

    pub(crate) fn has_peer(&self) -> bool {
        self.lock_runtime().is_some()
    }

    /// Builds the runtime: driver store, transport, IPC client, and peer. The peer is started so
    /// its receive loop and sync timer are running.
    pub(super) async fn boot(&self) {
        let store = LockStateStore::new(
            &self.0.name,
            self.0.leader.clone(),
            &self.0.users,
            self.0.delays,
            self.0.vault_url.clone(),
            self.0.topology,
        );

        // The hook points back at the device, which owns the store — a strong reference here would
        // leak the whole topology.
        let weak = Arc::downgrade(&self.0);
        let quirks = self.0.quirks;
        store.set_protocol_lock_hook(Box::new(move |user_id| {
            if let Some(inner) = weak.upgrade() {
                SimulatedDevice(inner).after_protocol_lock(user_id, quirks);
            }
        }));

        let incoming = self
            .0
            .transport
            .register(self.0.endpoint.clone(), &self.0.name);
        let backend = TransportBackend {
            transport: self.0.transport.clone(),
            name: self.0.name.clone(),
            source: self.0.source.clone(),
            incoming,
        };

        let token = CancellationToken::new();
        let ipc: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            backend,
            bitwarden_ipc::InMemorySessionRepository::<NoiseCryptoProviderState>::new(
                HashMap::new(),
            ),
        ));
        ipc.start(Some(token.clone()))
            .await
            .expect("IPC client should start");

        let peer = SharedUnlockPeer::create_for_test(
            store.clone(),
            ipc,
            self.0.timing.sync_interval,
            self.0.timing.vault_timeout_grace_period,
            self.0.timing.peer_stale_after,
        );
        peer.start(Some(token.clone()))
            .await
            .expect("Peer should start");

        *self.lock_runtime() = Some(DeviceRuntime { store, peer, token });
    }

    /// Simulates a process reload: the running peer is aborted and a brand-new transport, IPC
    /// client, driver, and peer are attached under the same [`Endpoint`], with lock state reset
    /// to locked and nothing recorded.
    pub(crate) async fn process_reload(&self) {
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::RELOAD,
            None,
            "process reload starting",
        );
        self.tear_down();
        self.boot().await;
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::RELOAD,
            None,
            "process reload complete",
        );
    }

    /// Takes the process down without bringing it back, so anything sent to it is unreachable — the
    /// failure a client sees when the app above it is not running.
    pub(crate) fn go_offline(&self) {
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::OFFLINE,
            None,
            "process going offline",
        );
        self.tear_down();
    }

    /// Brings a device back after [`SimulatedDevice::go_offline`], as a fresh process.
    pub(crate) async fn come_online(&self) {
        self.boot().await;
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::ONLINE,
            None,
            "process back online",
        );
    }

    pub(super) fn tear_down(&self) {
        if let Some(runtime) = self.lock_runtime().take() {
            runtime.token.cancel();
        }
        self.0.transport.unregister(&self.0.endpoint);
    }

    /// Unlocks locally (as the UI would) and then reports the event, which is the order a real
    /// client uses: the SDK owns the lock state and learns it only from the event.
    pub(crate) async fn manual_unlock(&self, user_id: UserId, user_key: &SymmetricCryptoKey) {
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::DEVICE_EVENT,
            Some(user_id),
            TEST_MANUAL_UNLOCK,
        );
        self.store()
            .apply_local(user_id, Some(user_key.clone()))
            .await;
        self.report_device_event(DeviceEvent::ManualUnlock {
            user_id,
            user_key: user_key.clone(),
        })
        .await;
    }

    /// Locks locally (as the UI would) and then reports the event.
    pub(crate) async fn manual_lock(&self, user_id: UserId) {
        emit_log(
            self.0.topology,
            &self.0.name,
            kind::DEVICE_EVENT,
            Some(user_id),
            TEST_MANUAL_LOCK,
        );
        self.store().apply_local(user_id, None).await;
        self.report_device_event(DeviceEvent::ManualLock { user_id })
            .await;
    }

    async fn report_device_event(&self, event: DeviceEvent) {
        let peer = self
            .lock_runtime()
            .as_ref()
            .map(|runtime| runtime.peer.clone());
        if let Some(peer) = peer {
            let _ = peer.handle_device_event(event).await;
        }
    }

    fn after_protocol_lock(&self, user_id: UserId, quirks: DeviceQuirks) {
        if quirks.replay_incoming_lock_as_manual_lock {
            emit_log(
                self.0.topology,
                &self.0.name,
                kind::DEVICE_EVENT,
                Some(user_id),
                REPLAYED_MANUAL_LOCK,
            );
            // Deliberately does not touch local state — the protocol already locked it. Only the
            // report is replayed, which is what a lock-state observable does. The peer already
            // recorded that lock when it applied it, so this should be a no-op.
            let device = self.clone();
            tokio::spawn(async move {
                device
                    .report_device_event(DeviceEvent::ManualLock { user_id })
                    .await;
            });
        }

        if let Some(delay) = quirks.reload_after_lock {
            let device = self.clone();
            tokio::spawn(async move {
                sleep(delay).await;
                device.process_reload().await;
            });
        }
    }

    fn lock_runtime(&self) -> std::sync::MutexGuard<'_, Option<DeviceRuntime>> {
        self.0
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
