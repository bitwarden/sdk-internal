//! A three-tier tree, and relaying through the middle of one.

use crate::{harness::SimulatedDevice, prelude::*};

/// The full client hierarchy, three tiers deep and branching at both of them:
///
/// ```text
/// desktop
/// ├── cli
/// ├── browser-a
/// │   ├── web-a1
/// │   └── web-a2
/// └── browser-b
/// ```
///
/// Every device holds user A. Each browser serves its own web clients and syncs up to the desktop
/// with one peer, so nothing above a browser ever addresses a web client directly.
struct Tree {
    topology: SharedUnlockTopology,
    browser_a: SimulatedDevice,
    web_a1: SimulatedDevice,
    web_a2: SimulatedDevice,
    /// Not addressed directly by any test; asserted through the topology-wide wait.
    _desktop: SimulatedDevice,
    _cli: SimulatedDevice,
    _browser_b: SimulatedDevice,
}

async fn build_tree() -> Tree {
    let topology = SharedUnlockTopology::new(fast_timing());
    let user_a = test_user(TestUserId::A).id;

    let desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user_a]),
    );
    let cli = topology.add_device(
        "cli",
        DeviceOptions::new(ClientType::Cli, &[user_a]).following(&desktop),
    );
    let browser_a = topology.add_device(
        "browser-a",
        DeviceOptions::new(ClientType::Browser, &[user_a])
            .following(&desktop)
            .with_vault_url(VAULT_URL),
    );
    let browser_b = topology.add_device(
        "browser-b",
        DeviceOptions::new(ClientType::Browser, &[user_a])
            .following(&desktop)
            .with_vault_url(VAULT_URL),
    );
    let web_a1 = topology.add_device(
        "web-a1",
        DeviceOptions::new(ClientType::Web, &[user_a])
            .following(&browser_a)
            .with_vault_url(VAULT_URL),
    );
    let web_a2 = topology.add_device(
        "web-a2",
        DeviceOptions::new(ClientType::Web, &[user_a])
            .following(&browser_a)
            .with_vault_url(VAULT_URL),
    );

    topology.start().await;
    Tree {
        topology,
        browser_a,
        web_a1,
        web_a2,
        _desktop: desktop,
        _cli: cli,
        _browser_b: browser_b,
    }
}

/// Unlocking the bottom leaf unlocks every branch, up and back down
///
/// ```text
/// web-a1 UNLOCKED --> browser-a UNLOCKED --> desktop UNLOCKED
///     --> cli / browser-b / web-a2 UNLOCKED
/// ```
#[tokio::test]
async fn unlock_web_routes_up_and_down_three_tiers() {
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    // 1. Unlock web-a1; all devices must become unlocked. That it reached browser-a at all also
    //    proves the browser accepted the web client's origin against `get_vault_url`.
    tree.web_a1.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &tree.topology, &user).await;

    // 2. Assert nothing relocked. Had the unlock not reached the top, the desktop would keep
    //    advertising `Locked` and relock the whole tree.
    bitwarden_threading::time::sleep(GRACE).await;
    assert_no_lock(&tree.topology, user.id, GRACE, 0);
}

/// Unlocking one of the desktop's followers unlocks all of them
///
/// The followers never hear from each other, so the CLI and browser-b learn the unlock only
/// because the desktop fans it back out.
///
/// ```text
///           browser-a UNLOCKED
///               |
///               v
///           desktop LOCKED --> UNLOCKED
///  +------------+------------+
///  v                         v
/// cli LOCKED --> UNLOCKED    browser-b LOCKED --> UNLOCKED
/// ```
#[tokio::test]
async fn unlock_browser_unlocks_all_desktop_followers() {
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    // 1. Unlock browser-a; all devices must become unlocked.
    tree.browser_a.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &tree.topology, &user).await;
}

/// A middle-tier browser that was offline for an unlock relays it to the whole tree on return
///
/// The V-shaped scenario with two tiers above the offline browser: its return carries the unlock
/// down to its own web client *and* up to the desktop, which fans it out to the other branches.
///
/// ```text
/// web-a1 UNLOCKED             web-a2 LOCKED --> UNLOCKED
///    \  (1)                      ^
///     x                         / (3)
///     browser-a offline --> back online (2) LOCKED --> UNLOCKED
///                                            |  (3)
///                                            v
///                                desktop --> cli / browser-b LOCKED --> UNLOCKED
/// ```
#[tokio::test]
async fn returning_browser_relays_web_unlock_to_tree() {
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    // 1. Take browser-a offline, then unlock web-a1.
    tree.browser_a.go_offline();
    tree.web_a1.manual_unlock(user.id, &user.key).await;

    // 2. Assert the unlock reached nobody. Sleeping out a couple of sync intervals first makes this
    //    about a delivery that was attempted, not one that had not been attempted yet.
    let timing = fast_timing();
    bitwarden_threading::time::sleep(timing.peer_stale_after + timing.sync_interval * 2).await;
    assert_eq!(tree.web_a2.store().peek(user.id), user.locked());

    // 3. Bring browser-a back as a fresh, locked process; web-a1's next retry reaches it, and the
    //    unlock travels both down to web-a2 and up to the desktop.
    tree.browser_a.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &tree.topology, &user).await;

    // 4. Assert no returning process's initial `Locked` relocked the tree a tick later.
    bitwarden_threading::time::sleep(GRACE).await;
    assert_user_state(TargetLockState::Unlocked, &tree.topology, &user);
}
