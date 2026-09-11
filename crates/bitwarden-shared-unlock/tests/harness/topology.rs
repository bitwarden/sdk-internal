//! Declares a set of devices and the hierarchy between them.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI32, Ordering},
};

use super::{
    LockDelays, TestUserId,
    client_type::ClientType,
    device::{DeviceOptions, SimulatedDevice},
    fast_timing,
    in_memory_ipc_transport::InMemoryIpcTransport,
    logs::{self, TopologyId},
    test_user,
};

/// Declares a set of devices and the hierarchy between them, then boots them top-down.
pub(crate) struct SharedUnlockTopology {
    id: TopologyId,
    started_at_ms: u128,
    transport: Arc<InMemoryIpcTransport>,
    timing: super::Timing,
    devices: Mutex<Vec<SimulatedDevice>>,
    /// Hands each device the id that separates it from others of the same client type.
    next_instance: AtomicI32,
    started: Mutex<bool>,
}

impl SharedUnlockTopology {
    pub(crate) fn new(timing: super::Timing) -> Self {
        logs::install();
        let id = TopologyId::next();
        Self {
            transport: InMemoryIpcTransport::new(id),
            id,
            started_at_ms: logs::now_ms(),
            timing,
            devices: Mutex::new(Vec::new()),
            next_instance: AtomicI32::new(1),
            started: Mutex::new(false),
        }
    }

    /// This topology's identity in the captured log, so assertions read only its own events.
    pub(crate) fn id(&self) -> TopologyId {
        self.id
    }

    /// Everything captured since this topology was created, for a failure message.
    pub(crate) fn captured_log(&self) -> String {
        logs::format_since(self.id, self.started_at_ms)
    }

    /// Declares a device. Which device it syncs up to is whichever one it was declared as
    /// following; its [`ClientType`] only decides whether it has a leader at all and what kind of
    /// endpoint that leader may be, since that is what the SDK's leader discovery keys off.
    pub(crate) fn add_device(&self, name: &str, options: DeviceOptions) -> SimulatedDevice {
        assert!(
            !*self.lock_started(),
            "cannot add a device after the topology has started"
        );

        match (options.client_type.has_leader(), &options.leader) {
            (false, Some(leader)) => panic!(
                "\"{name}\" is a {:?} client, which sits at the top of the hierarchy, so it cannot \
                 be given the leader \"{}\"",
                options.client_type,
                leader.name()
            ),
            (true, None) => panic!(
                "\"{name}\" is a {:?} client, so it needs a leader",
                options.client_type
            ),
            (true, Some(leader)) => assert!(
                options.client_type.can_follow(leader.endpoint()),
                "\"{name}\" is a {:?} client, so it cannot follow \"{}\" at {:?}",
                options.client_type,
                leader.name(),
                leader.endpoint()
            ),
            (false, None) => {}
        }

        assert!(
            options.client_type != ClientType::Web || options.vault_url.is_some(),
            "\"{name}\" is a web client and needs a vault_url: its leader validates a web source's \
             origin against get_vault_url and drops every message when it is absent"
        );

        let mut devices = self.lock_devices();
        assert!(
            !devices.iter().any(|device| device.name() == name),
            "a device named \"{name}\" is already declared"
        );

        let depth = options
            .leader
            .as_ref()
            .map(|leader| leader.depth() + 1)
            .unwrap_or(0);

        let device = SimulatedDevice::declare(
            name,
            options,
            self.next_instance.fetch_add(1, Ordering::SeqCst),
            self.timing,
            self.transport.clone(),
            self.id,
            depth,
        );
        devices.push(device.clone());
        device
    }

    /// Boots every device top-down, so a peer's opening sync is not sent before the peer above it
    /// has subscribed.
    pub(crate) async fn start(&self) {
        assert!(
            !*self.lock_started(),
            "cannot start the topology more than once"
        );

        let mut devices = self.lock_devices().clone();
        devices.sort_by_key(|device| device.depth());
        for device in &devices {
            device.boot().await;
        }
        *self.lock_started() = true;
    }

    pub(crate) fn devices(&self) -> Vec<SimulatedDevice> {
        self.lock_devices().clone()
    }

    fn lock_devices(&self) -> std::sync::MutexGuard<'_, Vec<SimulatedDevice>> {
        self.devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_started(&self) -> std::sync::MutexGuard<'_, bool> {
        self.started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for SharedUnlockTopology {
    fn drop(&mut self) {
        for device in self.lock_devices().iter() {
            device.tear_down();
        }
    }
}

/// The smallest topology that still has an above and a below: a desktop leader and a browser
/// follower. Users A and B are shared; user C exists only on the follower, so the leader has no
/// account for it.
pub(crate) struct SimpleTopology {
    pub(crate) topology: SharedUnlockTopology,
    pub(crate) leader: SimulatedDevice,
    pub(crate) follower: SimulatedDevice,
}

impl SimpleTopology {
    /// Declares the two devices and boots them.
    pub(crate) async fn make(delays: LockDelays) -> Self {
        let topology = SharedUnlockTopology::new(fast_timing());
        let (a, b, c) = (
            test_user(TestUserId::A).id,
            test_user(TestUserId::B).id,
            test_user(TestUserId::C).id,
        );

        let leader = topology.add_device(
            "desktop",
            DeviceOptions::new(ClientType::Desktop, &[a, b]).with_delays(delays),
        );
        let follower = topology.add_device(
            "browser",
            DeviceOptions::new(ClientType::Browser, &[a, b, c])
                .following(&leader)
                .with_delays(delays),
        );

        topology.start().await;
        Self {
            topology,
            leader,
            follower,
        }
    }
}
