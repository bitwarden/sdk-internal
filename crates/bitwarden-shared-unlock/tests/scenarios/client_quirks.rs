//! Behaviours real clients exhibit that the plain protocol does not model.

use crate::prelude::*;

/// Long enough for a lock to settle, the quirk's reload to fire, and the fresh process to be
/// wired up again.
const RELOAD_SETTLE: Duration = Duration::from_secs(3);

/// A follower replaying an applied lock as a manual lock changes nothing
///
/// ```text
/// follower UNLOCKED --> LOCKED --replay as manual lock--> stays LOCKED
///     |
/// leader UNLOCKED --> LOCKED
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
    bitwarden_threading::time::sleep(GRACE).await;

    // 3. Assert the quirk fired, and that nothing bounced back to unlocked.
    let replays = events_matching(&topology, |event| {
        event.field("detail") == Some(REPLAYED_MANUAL_LOCK)
    });
    assert_eq!(
        replays.len(),
        1,
        "The quirk should have replayed the lock exactly once; more than once is the replay \
         feeding back into the peer and being re-applied"
    );
    assert_eq!(replays[0].device(), "browser");

    assert_user_state(TargetLockState::Locked, &topology, &user);
}

/// A follower that restarts its process on every lock still converges, and can be unlocked again
///
/// ```text
/// follower UNLOCKED --> LOCKED --reload--> LOCKED --> UNLOCKED
///     |
/// leader UNLOCKED --> LOCKED --> UNLOCKED
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

    // 2. Lock the leader; all devices must become locked. That lock is what fires the quirk.
    leader.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &topology, &user).await;

    // 3. Let the reload run to completion, and assert it came back as a live process rather than
    //    leaving the device without a peer.
    bitwarden_threading::time::sleep(RELOAD_SETTLE).await;
    assert!(follower.has_peer());

    // 4. Unlock the leader; all devices must become unlocked. The reloaded follower has nothing
    //    recorded, so this only reaches it if its fresh receive loop is subscribed.
    leader.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;
}
