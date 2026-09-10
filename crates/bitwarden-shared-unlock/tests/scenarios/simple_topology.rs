//! Lock and unlock propagating between a leader and its follower, over [`SimpleTopology`]:
//!
//! ```text
//! follower (browser)
//!     |
//! leader (desktop)
//! ```

use crate::prelude::*;

/// Unlocking a follower unlocks its leader
///
/// ```text
/// follower 🔓
///     |
/// leader 🔒 --> 🔓
/// ```
#[tokio::test]
async fn unlock_follower_unlocks_leader() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
}

/// Locking a follower locks its leader
///
/// ```text
/// both 🔓 first, then the follower locks
///
/// follower 🔒
///     |
/// leader 🔓 --> 🔒
/// ```
#[tokio::test]
async fn lock_follower_locks_leader() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Lock the follower; all devices must become locked.
    simple.follower.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
}

/// Unlocking a leader unlocks its follower
///
/// ```text
/// follower 🔒 --> 🔓
///     |
/// leader 🔓
/// ```
#[tokio::test]
async fn unlock_leader_unlocks_follower() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the leader; all devices must become unlocked.
    simple.leader.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
}

/// Locking a leader locks its follower
///
/// ```text
/// both 🔓 first, then the leader locks
///
/// follower 🔓 --> 🔒
///     |
/// leader 🔒
/// ```
#[tokio::test]
async fn lock_leader_locks_follower() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower; all devices must become unlocked.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Lock the leader; all devices must become locked.
    simple.leader.manual_lock(user.id).await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
}

/// Unlocking one user leaves another user on the same devices locked
///
/// ```text
/// follower 🔓 A / 🔒 B
///     |
/// leader 🔓 A / 🔒 B
/// ```
#[tokio::test]
async fn unlock_user_a_leaves_user_b_locked() {
    let user_a = test_user(TestUserId::A);
    let user_b = test_user(TestUserId::B);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock user A on the follower; all devices must become unlocked for A.
    simple.follower.manual_unlock(user_a.id, &user_a.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user_a).await;

    // 2. User B must still be locked everywhere.
    assert_user_state(TargetLockState::Locked, &simple.topology, &user_b);
}
