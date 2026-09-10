//! Behaviours real clients exhibit that the plain protocol does not model.

use crate::prelude::*;

/// A follower replaying an applied lock as a manual lock changes nothing
///
/// ```text
/// follower 🔓 --> 🔒 --replay as manual lock--> stays 🔒
///     |
/// leader 🔓 --> 🔒
/// ```
#[tokio::test]
async fn replayed_lock_changes_nothing() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());
    let leader = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let follower = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&leader)
            .with_quirks(DeviceQuirks {
                replay_incoming_lock_as_manual_lock: true,
                ..DeviceQuirks::default()
            }),
    );
    topology.start().await;

    // 1. Unlock the follower; all devices must become unlocked.
    follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Lock the leader; all devices must become locked. The lock propagates down and the follower
    //    replays it into its own peer; the peer already recorded it when it applied it, so the
    //    replay must not disturb anything.
    leader.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &topology, &user).await;
    bitwarden_threading::time::sleep(grace(&topology)).await;

    // 3. Assert the quirk fired, and that nothing bounced back to unlocked.
    let replays = events_matching(&topology, |event| {
        event.field("detail") == Some(REPLAYED_MANUAL_LOCK)
    });
    assert!(
        !replays.is_empty(),
        "The quirk should have replayed the lock"
    );
    assert_eq!(replays[0].device(), "browser");

    assert_user_state(TargetLockState::Locked, &topology, &user);
}

/// A follower that restarts its process on every lock still converges, reloading exactly once
///
/// ```text
/// follower 🔓 --> 🔒 --reload--> 🔒  (exactly one reload)
///     |
/// leader 🔓 --> 🔒
/// ```
#[tokio::test]
async fn reload_after_lock_converges() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());
    let leader = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let follower = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&leader)
            .with_quirks(DeviceQuirks {
                reload_after_lock: Some(Duration::from_millis(10)),
                ..DeviceQuirks::default()
            }),
    );
    topology.start().await;

    // 1. Unlock the follower; all devices must become unlocked.
    follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Lock the leader, then wait for the follower's reload to finish rather than sleeping a
    //    fixed amount: these tests share a runtime, so when the quirk fires varies.
    leader.manual_lock(user.id).await;
    wait_for_event(
        &topology,
        "the browser's process reload to complete",
        CONVERGE_TIMEOUT,
        |event| {
            event.kind() == Some(kind::RELOAD)
                && event.field("detail") == Some("process reload complete")
        },
    )
    .await;
    // 3. Give it several ticks and assert it reloaded exactly once.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 6).await;

    let reloads: Vec<String> = events_matching(&topology, |event| {
        event.kind() == Some(kind::RELOAD) && event.device() == "browser"
    })
    .into_iter()
    .map(|event| event.field("detail").unwrap_or_default().to_owned())
    .collect();
    assert_eq!(
        reloads,
        vec!["process reload starting", "process reload complete"],
        "The quirk should have reloaded the process exactly once"
    );

    // 4. Assert the reloaded process is a fresh one, wired up and locked, and the leader agrees.
    assert!(follower.has_peer());
    assert_user_state(TargetLockState::Locked, &topology, &user);
}
