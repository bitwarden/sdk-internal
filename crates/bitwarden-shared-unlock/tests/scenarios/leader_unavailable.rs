//! What a peer does when the peer above it is not running.

use crate::prelude::*;

/// A follower unlocks and stays unlocked with no leader listening
///
/// ```text
/// follower 🔒 --> 🔓  (keeps retrying, stays 🔓)
///     |
///     x  leader offline
/// ```
#[tokio::test]
async fn unlock_follower_works_while_leader_offline() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Take the leader offline.
    simple.leader.go_offline();
    let offline_at = harness::now_ms();

    // 2. Unlock the follower and assert it applies locally — shared unlock propagates state, it
    //    does not gate on it.
    simple.follower.manual_unlock(user.id, &user.key).await;
    assert_eq!(simple.follower.store().peek(user.id), user.unlocked());

    // 3. Assert the follower keeps trying across ticks rather than giving up or dying. Waiting
    //    out the whole grace period, rather than just a few ticks, is what gives step 4 a log long
    //    enough to see a late self-relock in; the extra ticks only add sync attempts.
    bitwarden_threading::time::sleep(grace(&simple.topology)).await;
    assert!(
        count_unreachable(&simple.topology, "browser") > 1,
        "The follower should keep attempting to sync across ticks"
    );

    // 4. Assert it never relocked itself just because nobody is listening.
    assert_eq!(simple.follower.store().peek(user.id), user.unlocked());
    assert_no_lock(
        &simple.topology,
        user.id,
        grace(&simple.topology),
        offline_at,
    );
}

/// A leader that comes back online adopts the unlock it missed
///
/// ```text
/// follower 🔓
///     |
/// leader offline --> back online 🔒 --> 🔓
/// ```
#[tokio::test]
async fn returning_leader_adopts_follower_unlock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;
    let timing = fast_timing();

    // 1. Unlock the follower while the leader is offline and assert the syncs go nowhere.
    simple.leader.go_offline();
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(timing.sync_interval * 2).await;
    assert!(count_unreachable(&simple.topology, "browser") > 0);

    // 2. Bring the leader back; all devices must become unlocked. It returns as a fresh process:
    //    locked, nothing recorded. It has never seen the follower before, so the follower's next
    //    sync earns an immediate reply.
    simple.leader.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
    assert_eq!(simple.leader.store().peek(user.id), user.unlocked());
}

/// A browser extension with no desktop app running: its own syncs go nowhere, but it is still the
/// peer the web vault syncs to.
///
/// ```text
/// web 🔒 --> 🔓
///     |
/// browser 🔒 --> 🔓
///     |
///     x  desktop offline
/// ```
#[tokio::test]
async fn browser_serves_web_without_desktop() {
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

    // 1. Unlock the web client; all reachable devices must become unlocked. Serving downward is
    //    unaffected by having nowhere to sync upward.
    web.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Assert the browser's upward syncs were reported unreachable. They only show up once its
    //    timer fires — applying the web's sync does not itself make the browser send anything.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 2).await;
    assert!(
        count_unreachable(&topology, "browser") > 0,
        "The browser's upward syncs should be reported unreachable"
    );
}
