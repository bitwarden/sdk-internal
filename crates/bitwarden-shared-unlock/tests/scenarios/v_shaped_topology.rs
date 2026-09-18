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
    web_2: SimulatedDevice,
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
            web_2,
        }
    }
}

/// Unlocking one web client unlocks its sibling, via the browser between them
///
/// ```text
/// web-1 UNLOCKED    web-2 LOCKED --> UNLOCKED
///    \  (1)         ^
///     v           / (2)
///     browser LOCKED --> UNLOCKED
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
/// everyone UNLOCKED first, then web-1 locks
///
/// web-1 LOCKED    web-2 UNLOCKED --> LOCKED
///    \  (1)       ^
///     v         / (2)
///     browser UNLOCKED --> LOCKED
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
/// web-1 LOCKED --> UNLOCKED    web-2 LOCKED --> UNLOCKED
///     ^                            ^
///     |                            |
///     +------ browser UNLOCKED ----+
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
/// everyone UNLOCKED first, then the browser locks
///
/// web-1 UNLOCKED --> LOCKED    web-2 UNLOCKED --> LOCKED
///     ^                            ^
///     |                            |
///     +------- browser LOCKED -----+
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

/// A browser that was offline for an unlock relays it to the other tab on return
///
/// ```text
/// web-1 UNLOCKED             web-2 LOCKED --> UNLOCKED
///    \  (1)                     ^
///     x                        / (3)
///     browser offline --> back online (2) LOCKED --> UNLOCKED
/// ```
#[tokio::test]
async fn returning_browser_relays_web_unlock_to_sibling() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    // 1. Take the only path between the tabs offline, then unlock web-1.
    topology.browser.go_offline();
    topology.web_1.manual_unlock(user.id, &user.key).await;

    // 2. Assert the unlock reached nobody. Sleeping out a couple of sync intervals first makes this
    //    about a delivery that was attempted, not one that had not been attempted yet.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 2).await;
    assert_eq!(topology.web_2.store().peek(user.id), user.locked());

    // 3. Bring the browser back as a fresh, locked process; web-1's next retry reaches it, and it
    //    fans the unlock down to web-2.
    topology.browser.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology.topology, &user).await;

    // 4. Assert the returning browser's initial `Locked` did not relock both tabs a tick later.
    bitwarden_threading::time::sleep(GRACE).await;
    assert_user_state(TargetLockState::Unlocked, &topology.topology, &user);
}
