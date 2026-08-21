//! What a peer does when the peer above it is not running.

use crate::prelude::*;

#[tokio::test]
async fn keeps_working_locally_and_reports_undelivered_syncs() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;
    let timing = fast_timing();

    simple.leader.go_offline();
    let offline_at = harness::now_ms();

    // A local unlock still applies — shared unlock propagates state, it does not gate on it.
    simple.follower.manual_unlock(user.id, &user.key).await;
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.to_unlocked_lock_state()
    );

    // And the follower keeps trying across ticks rather than giving up or dying.
    bitwarden_threading::time::sleep(timing.sync_interval * 3).await;
    assert!(
        count_unreachable(&simple.topology, "browser") > 1,
        "The follower should keep attempting to sync across ticks"
    );

    // Crucially it must not relock itself just because nobody is listening.
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.to_unlocked_lock_state()
    );
    assert_no_lock(
        &simple.topology,
        user.id,
        grace(&simple.topology),
        offline_at,
    );
}

#[tokio::test]
async fn converges_once_the_leader_comes_back() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;
    let timing = fast_timing();

    simple.leader.go_offline();
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(timing.sync_interval * 2).await;
    assert!(count_unreachable(&simple.topology, "browser") > 0);

    // The leader returns as a fresh process: locked, nothing recorded. It has never seen the
    // follower before, so the follower's next sync earns an immediate reply.
    simple.leader.come_online().await;

    wait_for_device_reaching_state(
        &simple.topology,
        &simple.leader,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

#[tokio::test]
async fn a_device_whose_leader_never_existed_still_serves_the_peers_below_it() {
    // A browser extension with no desktop app running: its own syncs go nowhere, but it is
    // still the peer the web vault syncs to.
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());

    let missing_desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let browser = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&missing_desktop)
            .with_vault_url(VAULT_URL),
    );
    let web = topology.add_device(
        "web",
        DeviceOptions::new(ClientType::Web, &[user.id])
            .following(&browser)
            .with_vault_url(VAULT_URL),
    );

    topology.start().await;
    missing_desktop.go_offline();

    web.manual_unlock(user.id, &user.key).await;

    // Serving downward is unaffected by having nowhere to sync upward.
    wait_for_device_reaching_state(
        &topology,
        &browser,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    // The failing upward syncs only show up once the browser's timer fires — applying the web's
    // sync does not itself make the browser send anything.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 2).await;
    assert!(
        count_unreachable(&topology, "browser") > 0,
        "The browser's upward syncs should be reported unreachable"
    );
}
