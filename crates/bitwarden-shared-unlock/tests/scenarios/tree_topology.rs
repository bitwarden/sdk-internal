//! A three-tier tree, and relaying through the middle of one.

use crate::{
    harness::{LockDelays, SimulatedDevice},
    prelude::*,
};

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

/// A middle-tier browser that reloads on every lock keeps the desktop's lock after its reload, even
/// when the desktop quits right after locking, and carries it down to its web client rather than
/// taking the web client's older unlock back.
///
/// ```text
/// web UNLOCKED --> LOCKED (stays)
///    |
/// browser UNLOCKED --> LOCKED --reload--> LOCKED (stays)
///    |
/// desktop UNLOCKED --> LOCKED (manual) --> quits
/// ```
#[tokio::test]
async fn lock_desktop_then_quit_keeps_tree_locked() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());

    let desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let browser = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&desktop)
            .with_vault_url(VAULT_URL)
            .with_quirks(DeviceQuirks {
                reload_after_lock: Some(Duration::ZERO),
                ..DeviceQuirks::default()
            }),
    );
    let web = topology.add_device(
        "web",
        DeviceOptions::new(ClientType::Web, &[user.id])
            .following(&browser)
            .with_vault_url(VAULT_URL),
    );
    topology.start().await;

    // 1. Unlock the web client; all devices must become unlocked.
    web.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Lock the desktop and quit it as soon as the browser has applied the lock.
    let locked_at = harness::now_ms();
    desktop.manual_lock(user.id).await;
    let browser_locked = events_matching(&topology, |event| {
        event.device() == "browser" && event.kind() == Some("lock_end") && event.at >= locked_at
    });
    let deadline = harness::now_ms() + 2_000;
    let mut browser_locked = !browser_locked.is_empty();
    while !browser_locked && harness::now_ms() < deadline {
        bitwarden_threading::time::sleep(Duration::from_millis(1)).await;
        browser_locked = !events_matching(&topology, |event| {
            event.device() == "browser" && event.kind() == Some("lock_end") && event.at >= locked_at
        })
        .is_empty();
    }
    assert!(
        browser_locked,
        "trigger not reached: the browser should have applied the desktop's lock"
    );
    desktop.go_offline();

    // 3. Let the browser's reload-on-lock run, and assert it fired.
    bitwarden_threading::time::sleep(GRACE).await;
    let reloads = events_matching(&topology, |event| {
        event.device() == "browser" && event.kind() == Some("reload") && event.at >= locked_at
    });
    assert!(
        !reloads.is_empty(),
        "trigger not reached: the browser should have reloaded on the protocol lock"
    );

    // 4. The desktop's lock is newer than the web client's unlock: the remaining devices must end
    //    locked, and none may unlock again.
    let unlocks: Vec<String> = events_matching(&topology, |event| {
        event.kind() == Some("unlock_start") && event.at >= locked_at
    })
    .iter()
    .map(|event| format!("{} at {}ms", event.device(), event.at))
    .collect();
    assert!(
        unlocks.is_empty(),
        "No device may unlock after the desktop's lock, yet: {unlocks:?}\n{}",
        topology.captured_log()
    );
    assert_user_state(TargetLockState::Locked, &topology, &user);
}

/// A middle-tier browser relays the desktop's lock to its web client before locking itself, so the
/// web client locks even when the browser's process dies inside the lock (the browser extension
/// reloads there) and never gets to its next sync.
///
/// ```text
/// web UNLOCKED --> LOCKED
///    |
/// browser UNLOCKED --> lock starts --> process gone
///    |
/// desktop UNLOCKED --> LOCKED (manual)
/// ```
#[tokio::test]
async fn browser_relays_lock_before_dying_inside_it() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());

    let desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let browser = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&desktop)
            .with_vault_url(VAULT_URL)
            .with_delays(LockDelays {
                lock: GRACE,
                unlock: Duration::ZERO,
            }),
    );
    let _web = topology.add_device(
        "web",
        DeviceOptions::new(ClientType::Web, &[user.id])
            .following(&browser)
            .with_vault_url(VAULT_URL),
    );
    topology.start().await;

    // 1. Unlock the desktop; all devices must become unlocked.
    desktop.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Lock the desktop, and kill the browser as soon as it starts applying the lock.
    let locked_at = harness::now_ms();
    desktop.manual_lock(user.id).await;
    let browser_lock_started = || {
        !events_matching(&topology, |event| {
            event.device() == "browser"
                && event.kind() == Some("lock_start")
                && event.at >= locked_at
        })
        .is_empty()
    };
    let deadline = harness::now_ms() + 2_000;
    while !browser_lock_started() && harness::now_ms() < deadline {
        bitwarden_threading::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        browser_lock_started(),
        "trigger not reached: the browser should have started applying the desktop's lock"
    );
    browser.go_offline();

    // 3. The web client must still receive the lock and settle locked, like the desktop.
    wait_for_devices_reaching_state(TargetLockState::Locked, &topology, &user).await;
}
