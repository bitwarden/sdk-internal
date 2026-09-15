//! Two web clients and one browser

use crate::{harness::SimulatedDevice, prelude::*};

/// One browser extension serving two web vault tabs:
///
/// ```text
/// web-1     web-2
///     \     /
///     browser
/// ```
struct VShapedTopology {
    topology: SharedUnlockTopology,
    browser: SimulatedDevice,
    web_1: SimulatedDevice,
    /// Not addressed directly by any test; asserted through the topology-wide wait.
    _web_2: SimulatedDevice,
}

impl VShapedTopology {
    async fn make() -> Self {
        let topology = SharedUnlockTopology::new(fast_timing());
        let user_a = test_user(TestUserId::A).id;

        let desktop = topology.add_device(
            "desktop",
            DeviceOptions::new(ClientType::Desktop, &[user_a]),
        );
        let browser = topology.add_device(
            "browser",
            DeviceOptions::new(ClientType::Browser, &[user_a])
                .following(&desktop)
                .with_vault_url(VAULT_URL),
        );
        let web_1 = topology.add_device(
            "web-1",
            DeviceOptions::new(ClientType::Web, &[user_a])
                .following(&browser)
                .with_vault_url(VAULT_URL),
        );
        let web_2 = topology.add_device(
            "web-2",
            DeviceOptions::new(ClientType::Web, &[user_a])
                .following(&browser)
                .with_vault_url(VAULT_URL),
        );

        topology.start().await;
        desktop.go_offline();

        Self {
            topology,
            browser,
            web_1,
            _web_2: web_2,
        }
    }
}

/// Unlocking one web client unlocks its sibling, via the browser between them
///
/// ```text
/// web-1 🔓    web-2 🔒 --> 🔓
///     \   (1)   ^
///      v       / (2)
///      browser 🔒 --> 🔓
/// ```
#[tokio::test]
async fn unlock_web_unlocks_sibling_web() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    // 1. Unlock web-1; all devices must become unlocked. Two hops: up to the browser, which applies
    //    it, then back down to the sibling tab.
    topology.web_1.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology.topology, &user).await;
}

/// Locking one web client locks its sibling, via the browser between them
///
/// ```text
/// everyone 🔓 first, then web-1 locks
///
/// web-1 🔒    web-2 🔓 --> 🔒
///     \   (1)   ^
///      v       / (2)
///      browser 🔓 --> 🔒
/// ```
#[tokio::test]
async fn lock_web_locks_sibling_web() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    // 1. Unlock web-1; all devices must become unlocked.
    topology.web_1.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology.topology, &user).await;

    // 2. Lock web-1; all devices must become locked.
    topology.web_1.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &topology.topology, &user).await;
}

/// Unlocking the browser unlocks both web clients below it
///
/// ```text
/// web-1 🔒 --> 🔓    web-2 🔒 --> 🔓
///          ^          ^
///           \        /
///            browser 🔓
/// ```
#[tokio::test]
async fn unlock_browser_unlocks_both_webs() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    // 1. Unlock the browser; all devices must become unlocked.
    topology.browser.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology.topology, &user).await;
}

/// Locking the browser locks both web clients below it
///
/// ```text
/// everyone 🔓 first, then the browser locks
///
/// web-1 🔓 --> 🔒    web-2 🔓 --> 🔒
///          ^          ^
///           \        /
///            browser 🔒
/// ```
#[tokio::test]
async fn lock_browser_locks_both_webs() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    // 1. Unlock the browser; all devices must become unlocked.
    topology.browser.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology.topology, &user).await;

    // 2. Lock the browser; all devices must become locked.
    topology.browser.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &topology.topology, &user).await;
}
