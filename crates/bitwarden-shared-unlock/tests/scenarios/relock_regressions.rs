//! The relock bugs the protocol rewrite was meant to fix.

use crate::prelude::*;

/// Four unlock/lock cycles in a row never relock spuriously, with slow lock delays so every
/// transition has time to be undone by a stale advertisement
///
/// ```text
/// follower 🔓 --> 🔒 --> 🔓 --> 🔒 ...
///     |
/// leader follows, and neither side ever flips back on its own
/// ```
#[tokio::test]
async fn repeated_cycles_never_relock_spuriously() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;
    let grace = grace(&simple.topology);

    for _ in 0..4 {
        // 1. Unlock the follower; all devices must become unlocked and stay that way.
        simple.follower.manual_unlock(user.id, &user.key).await;
        wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
        bitwarden_threading::time::sleep(grace).await;
        assert_no_lock(&simple.topology, user.id, grace, 0);

        // 2. Lock the follower; all devices must become locked.
        simple.follower.manual_lock(user.id).await;
        wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
        bitwarden_threading::time::sleep(grace).await;
    }
}

/// A leader keeps syncing while a lock settles, or the follower's suppression lapses and its own
/// vault timeout locks it
///
/// ```text
/// follower 🔓  (suppression must be renewed within one interval + grace)
///     |
/// leader 🔓 --sync--> follower
/// ```
#[tokio::test]
async fn leader_keeps_syncing_while_lock_settles() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;
    let timing = fast_timing();

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Wait out one sync interval plus the grace period and assert the follower is still being
    //    synced to — otherwise the suppression it was last granted lapses and its own vault timeout
    //    is free to fire.
    let observed_from = harness::now_ms();
    bitwarden_threading::time::sleep(
        timing.sync_interval + timing.vault_timeout_grace_period + Duration::from_millis(200),
    )
    .await;

    assert_still_responsive(&simple.topology, "browser", observed_from);
}

/// A user the leader has no account for stays unlocked on the follower that does
///
/// ```text
/// follower 🔓 C  --> stays 🔓
///     |
/// leader (no account for C)
/// ```
#[tokio::test]
async fn unknown_user_stays_unlocked_on_follower() {
    let user = test_user(TestUserId::C);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;

    // 1. Unlock user C on the follower and let several sync round-trips pass — enough for the
    //    leader to advertise its own view of user C.
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 4).await;

    // 2. Assert user C stayed unlocked on the follower.
    assert_no_lock(&simple.topology, user.id, grace(&simple.topology), 0);
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.unlocked(),
        "A user the leader does not know must stay unlocked on the device that does"
    );
}
