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

/// An unlock on a leaf travels up to the browser and back down to the sibling:
///
/// ```text
/// web-1 🔓    web-2 🔒 --> 🔓
///     \   (1)   ^
///      v       / (2)
///      browser 🔒 --> 🔓
/// ```
#[tokio::test]
async fn an_unlock_in_one_web_client_reaches_the_other() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.web_1.manual_unlock(user.id, &user.key).await;

    // Two hops: up to the browser, which applies it, then back down to the sibling tab.
    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

/// Same two hops in reverse, once the whole topology is unlocked:
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
async fn a_lock_in_one_web_client_reaches_the_other() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.web_1.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    topology.web_1.manual_lock(user.id).await;

    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

/// An unlock at the hub fans out one hop to both leaves:
///
/// ```text
/// web-1 🔒 --> 🔓    web-2 🔒 --> 🔓
///          ^          ^
///           \        /
///            browser 🔓
/// ```
#[tokio::test]
async fn an_unlock_in_the_browser_reaches_both_web_clients() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.browser.manual_unlock(user.id, &user.key).await;

    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

/// A lock at the hub fans out one hop to both leaves:
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
async fn a_lock_in_the_browser_reaches_both_web_clients() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.browser.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    topology.browser.manual_lock(user.id).await;

    wait_for_topology_reaching_state(
        &topology.topology,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}
