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
        let a = test_user(TestUserId::A).id;

        let desktop = topology.add_device("desktop", DeviceOptions::new(ClientType::Desktop, &[a]));
        let browser = topology.add_device(
            "browser",
            DeviceOptions::new(ClientType::Browser, &[a])
                .following(&desktop)
                .with_vault_url(VAULT_URL),
        );
        let web_1 = topology.add_device(
            "web-1",
            DeviceOptions::new(ClientType::Web, &[a])
                .following(&browser)
                .with_vault_url(VAULT_URL),
        );
        let web_2 = topology.add_device(
            "web-2",
            DeviceOptions::new(ClientType::Web, &[a])
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

#[tokio::test]
async fn an_unlock_in_one_web_client_reaches_the_other() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.web_1.manual_unlock(user.id, &user.key).await;

    // Two hops: up to the browser, which applies it, then back down to the sibling tab. Nothing
    // else can carry it, since the desktop above the browser is offline.
    wait_for_device_reaching_state(
        &topology.topology,
        &topology.web_2,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
    assert_eq!(
        topology.browser.store().peek(user.id),
        user.to_unlocked_lock_state(),
        "The relaying browser must hold the state it passed on"
    );
}

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

    wait_for_device_reaching_state(
        &topology.topology,
        &topology.web_2,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

#[tokio::test]
async fn an_unlock_in_the_browser_reaches_both_web_clients() {
    let user = test_user(TestUserId::A);
    let topology = VShapedTopology::make().await;

    topology.browser.manual_unlock(user.id, &user.key).await;

    for web in [&topology.web_1, &topology.web_2] {
        wait_for_device_reaching_state(
            &topology.topology,
            web,
            user.id,
            &user.to_unlocked_lock_state(),
            CONVERGE_TIMEOUT,
        )
        .await;
    }
}
