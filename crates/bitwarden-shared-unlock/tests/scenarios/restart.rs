//! What a peer does when a process restarts and comes up with nothing recorded.

use crate::prelude::*;

/// A restarted follower comes up locked and relearns the unlock from its leader
///
/// ```text
/// follower UNLOCKED --restart--> LOCKED --> UNLOCKED
///     |
/// leader UNLOCKED
/// ```
#[tokio::test]
async fn restart_follower_adopts_leader_unlock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Restart the follower. It comes up locked with nothing recorded, so it loses every
    //    comparison and the leader's unlock wins it back.
    simple.follower.process_reload().await;
    assert_eq!(simple.follower.store().peek(user.id), user.locked());
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
}

/// A restarted leader comes up locked and relearns the unlock from its follower
///
/// ```text
/// follower UNLOCKED
///     |
/// leader UNLOCKED --restart--> LOCKED --> UNLOCKED
/// ```
#[tokio::test]
async fn restart_leader_adopts_follower_unlock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Restart the leader. It has never seen the follower before, so the follower's next sync
    //    earns an immediate reply. The Noise session also has to be re-established, which costs one
    //    extra round.
    simple.leader.process_reload().await;
    assert_eq!(simple.leader.store().peek(user.id), user.locked());
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
}

/// A restarted follower advertises `Locked`, which must not lock its leader
///
/// ```text
/// follower UNLOCKED --restart--> LOCKED (advertises Locked)
///     |
/// leader UNLOCKED --> stays UNLOCKED
/// ```
#[tokio::test]
async fn restart_follower_keeps_leader_unlocked() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Restart the follower and let a grace period pass.
    let restarted_at = harness::now_ms();
    simple.follower.process_reload().await;

    bitwarden_threading::time::sleep(GRACE).await;

    // 3. Assert the leader stayed unlocked. A restarted peer advertises `Locked` so its leader
    //    learns it exists; if that announcement were treated as authoritative it would lock the
    //    session on every restart.
    assert_eq!(
        simple.leader.store().peek(user.id),
        user.unlocked(),
        "A restart must not lock the peer above"
    );
    assert_no_lock(&simple.topology, user.id, GRACE, restarted_at);
}

/// A restarted leader advertises `Locked`, which must not lock its follower
///
/// ```text
/// follower UNLOCKED --> stays UNLOCKED
///     |
/// leader UNLOCKED --restart--> LOCKED (advertises Locked)
/// ```
#[tokio::test]
async fn restart_leader_keeps_follower_unlocked() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Restart the leader and let a grace period pass.
    let restarted_at = harness::now_ms();
    simple.leader.process_reload().await;

    bitwarden_threading::time::sleep(GRACE).await;

    // 3. The follower must still be unlocked. A restarted leader advertises `Locked`; if that
    //    announcement were treated as authoritative it would lock everything below it.
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.unlocked(),
        "A restart must not lock the peers below"
    );
    assert_no_lock(&simple.topology, user.id, GRACE, restarted_at);
}

/// A follower that restarts before its manual lock reached the leader still locks the leader,
/// rather than relearning the older unlock from it
///
/// ```text
/// follower UNLOCKED --lock--> LOCKED --restart--> LOCKED
///     x  lock sync lost
/// leader UNLOCKED --> LOCKED
/// ```
#[tokio::test]
async fn restart_before_lock_sync_keeps_lock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Cut the leader off, so the follower's lock never reaches it.
    simple.leader.disconnect();
    simple.follower.manual_lock(user.id).await;

    // 3. Restart the follower, then restore the link. The leader still advertises the older unlock;
    //    the follower must remember its lock and win with it rather than adopt the unlock.
    simple.follower.process_reload().await;
    simple.leader.reconnect();

    wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
    bitwarden_threading::time::sleep(GRACE).await;
    assert_user_state(TargetLockState::Locked, &simple.topology, &user);
}
