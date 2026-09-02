//! What a peer does when a process restarts and comes up with nothing recorded.

use crate::prelude::*;

#[tokio::test]
async fn a_restarted_follower_adopts_its_leaders_unlocked_state() {
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

    // The restarted follower comes up locked with nothing recorded, so it loses every
    // comparison and the leader's unlock wins.
    simple.follower.process_reload().await;
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.to_locked_lock_state()
    );

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
async fn a_restarted_leader_adopts_its_followers_unlocked_state() {
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

    simple.leader.process_reload().await;
    assert_eq!(
        simple.leader.store().peek(user.id),
        user.to_locked_lock_state()
    );

    // The restarted leader has never seen the follower before, so the follower's next sync
    // earns an immediate reply. The Noise session also has to be re-established, which
    // costs one extra round.
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
async fn a_restarted_follower_does_not_relock_its_leader() {
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

    let restarted_at = harness::now_ms();
    simple.follower.process_reload().await;

    let grace = grace(&simple.topology);
    bitwarden_threading::time::sleep(grace).await;

    // A restarted peer advertises `Locked` so its leader learns it exists. If that announcement
    // were treated as authoritative it would lock the session on every restart.
    assert_eq!(
        simple.leader.store().peek(user.id),
        user.to_unlocked_lock_state(),
        "A restart must not lock the peer above"
    );
    assert_no_lock(&simple.topology, user.id, grace, restarted_at);
}
