//! Peers that reached the same state independently settling on one date.

use crate::prelude::*;

/// Two peers can reach the same lock state independently, at different times, if they cannot
/// see each other while it happens. Once they can, they must settle on one date and not
/// merely on one state: the side holding the older date otherwise re-advertises it on every
/// tick forever.
#[tokio::test]
async fn peers_that_unlocked_independently_settle_on_one_date() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // With the leader unreachable, both sides unlock on their own and stamp their own dates.
    simple.leader.go_offline();
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(Duration::from_millis(30)).await;
    simple.leader.come_online().await;
    simple.leader.manual_unlock(user.id, &user.key).await;

    let follower_date = simple
        .follower
        .recorded_date(user.id)
        .expect("The follower recorded its own unlock");
    let leader_date = simple
        .leader
        .recorded_date(user.id)
        .expect("The leader recorded its own unlock");
    assert_ne!(
        follower_date, leader_date,
        "The two unlocks should be far enough apart to have different dates"
    );

    // They already agree on the state, so only the date has to travel.
    let newest = follower_date.max(leader_date);
    for _ in 0..40 {
        if simple.follower.recorded_date(user.id) == Some(newest)
            && simple.leader.recorded_date(user.id) == Some(newest)
        {
            return;
        }
        bitwarden_threading::time::sleep(Duration::from_millis(25)).await;
    }

    panic!(
        "Peers never settled on one date: follower={:?} leader={:?} (expected {newest}){}",
        simple.follower.recorded_date(user.id),
        simple.leader.recorded_date(user.id),
        simple.topology.captured_log()
    );
}
