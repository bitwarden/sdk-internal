//! Lock and unlock propagating between a leader and its follower, over [`SimpleTopology`].

use crate::prelude::*;

#[tokio::test]
async fn unlock_from_a_follower_reaches_its_leader() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    simple.follower.manual_unlock(user.id, &user.key).await;

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
async fn lock_from_a_follower_reaches_its_leader() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &simple.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    simple.follower.manual_lock(user.id).await;

    wait_for_device_reaching_state(
        &simple.topology,
        &simple.leader,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

#[tokio::test]
async fn unlock_from_a_leader_reaches_its_follower() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    simple.leader.manual_unlock(user.id, &user.key).await;

    wait_for_device_reaching_state(
        &simple.topology,
        &simple.follower,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

#[tokio::test]
async fn lock_from_a_leader_reaches_its_follower() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &simple.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    simple.leader.manual_lock(user.id).await;

    wait_for_device_reaching_state(
        &simple.topology,
        &simple.follower,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
}

#[tokio::test]
async fn an_event_does_not_touch_another_user() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &simple.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    assert_eq!(
        simple.leader.store().peek(test_user(TestUserId::B).id),
        test_user(TestUserId::B).to_locked_lock_state(),
        "An unlock for one user must not unlock another"
    );
}
