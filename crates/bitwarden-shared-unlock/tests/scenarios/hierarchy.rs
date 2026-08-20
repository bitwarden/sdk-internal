//! Multi-tier topologies, and relaying through the middle of one.

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
    desktop: SimulatedDevice,
    cli: SimulatedDevice,
    browser_a: SimulatedDevice,
    browser_b: SimulatedDevice,
    web_a1: SimulatedDevice,
    web_a2: SimulatedDevice,
}

async fn build_tree() -> Tree {
    let topology = SharedUnlockTopology::new(fast_timing());
    let a = test_user(TestUserId::A).id;

    let desktop = topology.add_device("desktop", DeviceOptions::new(ClientType::Desktop, &[a]));
    let cli = topology.add_device(
        "cli",
        DeviceOptions::new(ClientType::Cli, &[a]).following(&desktop),
    );
    let browser_a = topology.add_device(
        "browser-a",
        DeviceOptions::new(ClientType::Browser, &[a])
            .following(&desktop)
            .with_vault_url(VAULT_URL),
    );
    let browser_b = topology.add_device(
        "browser-b",
        DeviceOptions::new(ClientType::Browser, &[a])
            .following(&desktop)
            .with_vault_url(VAULT_URL),
    );
    let web_a1 = topology.add_device(
        "web-a1",
        DeviceOptions::new(ClientType::Web, &[a])
            .following(&browser_a)
            .with_vault_url(VAULT_URL),
    );
    let web_a2 = topology.add_device(
        "web-a2",
        DeviceOptions::new(ClientType::Web, &[a])
            .following(&browser_a)
            .with_vault_url(VAULT_URL),
    );

    topology.start().await;
    Tree {
        topology,
        desktop,
        cli,
        browser_a,
        browser_b,
        web_a1,
        web_a2,
    }
}

#[tokio::test]
async fn routes_in_both_directions_across_three_tiers() {
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    tree.web_a1.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &tree.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    // The web client's sync reached its browser and was applied, which also proves the browser
    // accepted its origin against `get_vault_url`.
    assert_eq!(
        tree.browser_a.store().peek(user.id),
        user.to_unlocked_lock_state()
    );

    let sent = |from: &str, to: &str| {
        !events_matching(&tree.topology, |event| {
            event.kind() == Some(kind::IPC_SEND)
                && event.device() == from
                && event
                    .field("detail")
                    .is_some_and(|detail| detail.contains(to))
        })
        .is_empty()
    };
    assert!(
        sent("web-a1", "browser-a"),
        "web should sync up to its browser"
    );
    assert!(
        sent("browser-a", "web-a1"),
        "browser should sync down to the web"
    );
    assert!(
        sent("browser-a", "desktop"),
        "browser should sync up to the desktop"
    );
    assert!(
        sent("desktop", "browser-a"),
        "desktop should sync down to the browser"
    );
}

#[tokio::test]
async fn relays_an_unlock_that_entered_the_middle_from_below() {
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    tree.web_a1.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &tree.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    // The unlock has to have travelled two hops, web-a1 -> browser-a -> desktop.
    assert_eq!(
        tree.desktop.store().peek(user.id),
        user.to_unlocked_lock_state(),
        "An unlock entering at the bottom must reach the top of the hierarchy"
    );

    // If it had not, the desktop would keep advertising `Locked` and relock the whole tree.
    let grace = grace(&tree.topology);
    bitwarden_threading::time::sleep(grace).await;
    assert_no_lock(&tree.topology, user.id, grace, 0);
}

#[tokio::test]
async fn a_leader_serves_several_followers() {
    // The desktop's three followers — a CLI and two browsers — never hear from each other, so each
    // one learns the unlock only because the desktop fans it back out.
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    tree.browser_a.manual_unlock(user.id, &user.key).await;

    for device in [&tree.desktop, &tree.cli, &tree.browser_b] {
        wait_for_device_reaching_state(
            &tree.topology,
            device,
            user.id,
            &user.to_unlocked_lock_state(),
            CONVERGE_TIMEOUT,
        )
        .await;
    }
}

#[tokio::test]
async fn a_browser_serves_several_web_clients() {
    // Two tabs against one extension. The unlock in one has to come back down to the other, which
    // means the browser fans out to every web client below it rather than only to the one that
    // last spoke to it.
    let user = test_user(TestUserId::A);
    let tree = build_tree().await;

    tree.web_a1.manual_unlock(user.id, &user.key).await;

    wait_for_device_reaching_state(
        &tree.topology,
        &tree.web_a2,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}
