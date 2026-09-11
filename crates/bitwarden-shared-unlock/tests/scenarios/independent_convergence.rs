//! Peers that reached the same state independently settling on one date.

use crate::prelude::*;

/// Two peers that unlocked while partitioned settle on one date
///
/// ```text
/// follower 🔓 @ t1        follower 🔓 @ t2
///     x        --join-->      |
/// leader 🔓 @ t2          leader 🔓 @ t2
/// ```
///
/// Two peers can reach the same lock state independently, at different times, if they cannot
/// see each other while it happens. Once they can, they must settle on one date and not
/// merely on one state: the side holding the older date otherwise re-advertises it on every
/// tick forever.
#[tokio::test]
async fn independent_unlocks_settle_on_one_date() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the follower while the leader is down, so its unlock reaches nobody and it alone
    //    stamps that date. The leader can only unlock once it is back up — an offline device has no
    //    process to unlock — so it stamps its own, later date on the way in.
    simple.leader.go_offline();
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(Duration::from_millis(30)).await;
    simple.leader.come_online().await;
    simple.leader.manual_unlock(user.id, &user.key).await;

    // 2. Assert the two dates really are different.
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

    // 3. Assert both sides settle on the newest date. They already agree on the state, so only the
    //    date has to travel.
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
