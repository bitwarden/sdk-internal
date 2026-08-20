//! The relock bugs the protocol rewrite was meant to fix.

use crate::prelude::*;

#[tokio::test]
async fn repeated_unlock_and_lock_cycles_never_relock_spuriously() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;
    let grace = grace(&simple.topology);

    for _ in 0..4 {
        simple.follower.manual_unlock(user.id, &user.key).await;
        wait_for_topology_reaching_state(
            &simple.topology,
            user.id,
            &user.to_unlocked_lock_state(),
            CONVERGE_TIMEOUT,
        )
        .await;
        bitwarden_threading::time::sleep(grace).await;
        assert_no_lock(&simple.topology, user.id, grace, 0);

        simple.follower.manual_lock(user.id).await;
        wait_for_topology_reaching_state(
            &simple.topology,
            user.id,
            &user.to_locked_lock_state(),
            CONVERGE_TIMEOUT,
        )
        .await;
        bitwarden_threading::time::sleep(grace).await;
    }
}

#[tokio::test]
async fn keeps_syncing_to_a_follower_while_a_lock_is_still_settling() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;
    let timing = fast_timing();

    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &simple.topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    // The follower needs a sync within one interval plus the grace period, otherwise the
    // suppression it was last granted lapses and its own vault timeout is free to fire.
    let observed_from = harness::now_ms();
    bitwarden_threading::time::sleep(
        timing.sync_interval + timing.vault_timeout_grace_period + Duration::from_millis(200),
    )
    .await;

    assert_still_responsive(&simple.topology, "browser", observed_from);
}

#[tokio::test]
async fn does_not_relock_a_user_the_leader_has_no_account_for() {
    let user = test_user(TestUserId::C);
    let simple = SimpleTopology::make(SLOW_DELAYS).await;

    simple.follower.manual_unlock(user.id, &user.key).await;
    // Several sync round-trips: enough for the leader to advertise its own view of user C.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 4).await;

    assert_no_lock(&simple.topology, user.id, grace(&simple.topology), 0);
    assert_eq!(
        simple.follower.store().peek(user.id),
        user.to_unlocked_lock_state(),
        "A user the leader does not know must stay unlocked on the device that does"
    );
}
