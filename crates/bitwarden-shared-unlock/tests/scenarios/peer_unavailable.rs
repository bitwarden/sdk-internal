//! What a peer does when the peer on the other end of its link is not running, and what it
//! adopts when that peer comes back.

use crate::prelude::*;

/// A follower unlocks and stays unlocked with no leader listening
///
/// ```text
/// follower LOCKED --> UNLOCKED  (keeps retrying, stays UNLOCKED)
///     |
///     x  leader offline
/// ```
#[tokio::test]
async fn unlock_follower_works_while_leader_offline() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Take the leader offline.
    simple.leader.go_offline();
    let offline_at = harness::now_ms();

    // 2. Unlock the follower and assert it applies locally. Shared unlock propagates state, it does
    //    not gate on it.
    simple.follower.manual_unlock(user.id, &user.key).await;
    assert_eq!(simple.follower.store().peek(user.id), user.unlocked());

    // 3. Assert the follower keeps trying across ticks rather than giving up or dying. Waiting out
    //    the whole grace period, rather than just a few ticks, is what gives step 4 a log long
    //    enough to see a late self-relock in; the extra ticks only add sync attempts.
    bitwarden_threading::time::sleep(GRACE).await;
    assert!(
        count_unreachable(&simple.topology, "browser") > 1,
        "The follower should keep attempting to sync across ticks"
    );

    // 4. Assert it never relocked itself just because nobody is listening.
    assert_eq!(simple.follower.store().peek(user.id), user.unlocked());
    assert_no_lock(&simple.topology, user.id, GRACE, offline_at);
}

/// A leader that comes back online adopts the unlock it missed
///
/// ```text
/// follower UNLOCKED
///     |
/// leader offline --> back online LOCKED --> UNLOCKED
/// ```
#[tokio::test]
async fn returning_leader_adopts_follower_unlock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;
    let timing = fast_timing();

    // 1. Unlock the follower while the leader is offline and assert the syncs go nowhere.
    simple.leader.go_offline();
    simple.follower.manual_unlock(user.id, &user.key).await;
    bitwarden_threading::time::sleep(timing.sync_interval * 2).await;
    assert!(count_unreachable(&simple.topology, "browser") > 0);

    // 2. Bring the leader back; all devices must become unlocked. It returns as a fresh process:
    //    locked, nothing recorded. It has never seen the follower before, so the follower's next
    //    sync earns an immediate reply.
    simple.leader.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
    assert_eq!(simple.leader.store().peek(user.id), user.unlocked());
}

/// A leader that comes back online adopts the lock it missed
///
/// ```text
/// follower UNLOCKED --> LOCKED
///     |
/// leader offline --> back online LOCKED
/// ```
#[tokio::test]
async fn returning_leader_adopts_follower_lock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock everything, then lock the follower with the leader down.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
    simple.leader.go_offline();
    simple.follower.manual_lock(user.id).await;
    let locked_at = simple
        .follower
        .recorded_date(user.id)
        .expect("The follower recorded its own lock");

    // 2. Bring the leader back. It returns locked already, so agreeing on the state proves nothing;
    //    what has to travel is the follower's lock date.
    simple.leader.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
    assert_eq!(
        wait_for_one_recorded_date(&simple.topology, user.id).await,
        locked_at,
        "The returning leader should adopt the follower's lock date, not stamp its own"
    );
}

/// A follower that comes back online adopts the unlock it missed
///
/// ```text
/// follower offline --> back online LOCKED --> UNLOCKED
///     |
/// leader UNLOCKED
/// ```
#[tokio::test]
async fn returning_follower_adopts_leader_unlock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock the leader while the follower is down.
    simple.follower.go_offline();
    simple.leader.manual_unlock(user.id, &user.key).await;

    // 2. Bring the follower back; all devices must become unlocked. It returns locked with nothing
    //    recorded, so it loses every comparison and the leader's unlock wins it over.
    simple.follower.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
}

/// A follower that comes back online adopts the lock it missed
///
/// ```text
/// follower offline --> back online LOCKED
///     |
/// leader UNLOCKED --> LOCKED
/// ```
#[tokio::test]
async fn returning_follower_adopts_leader_lock() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock everything, then lock the leader with the follower down.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;
    simple.follower.go_offline();
    simple.leader.manual_lock(user.id).await;
    let locked_at = simple
        .leader
        .recorded_date(user.id)
        .expect("The leader recorded its own lock");

    // 2. Bring the follower back. It returns locked already, so agreeing on the state proves
    //    nothing; what has to travel is the leader's lock date.
    simple.follower.come_online().await;
    wait_for_devices_reaching_state(TargetLockState::Locked, &simple.topology, &user).await;
    assert_eq!(
        wait_for_one_recorded_date(&simple.topology, user.id).await,
        locked_at,
        "The returning follower should adopt the leader's lock date, not stamp its own"
    );
}

/// Two peers that unlocked while partitioned settle on one date
///
/// ```text
/// follower UNLOCKED @ t1        follower UNLOCKED @ t2
///     x        --join-->            |
/// leader UNLOCKED @ t2          leader UNLOCKED @ t2
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

    // Read the follower's date while the leader is still down: once the two can see each other,
    // the leader's later date can reach the follower at any tick and overwrite it.
    let follower_date = simple
        .follower
        .recorded_date(user.id)
        .expect("The follower recorded its own unlock");

    simple.leader.come_online().await;
    simple.leader.manual_unlock(user.id, &user.key).await;

    // 2. Assert the two dates really are different.
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
    assert_eq!(
        wait_for_one_recorded_date(&simple.topology, user.id).await,
        follower_date.max(leader_date),
        "The older date should have been replaced, not merely coexisted with"
    );
}

/// Two peers that locked while partitioned settle on one date
///
/// ```text
/// follower LOCKED @ t1          follower LOCKED @ t2
///     x        --join-->            |
/// leader LOCKED @ t2            leader LOCKED @ t2
/// ```
///
/// The lock direction of [`independent_unlocks_settle_on_one_date`]. Both sides end up `Locked`
/// whatever happens, so the state says nothing about whether the dates converged; only the dates
/// do.
#[tokio::test]
async fn independent_locks_settle_on_one_date() {
    let user = test_user(TestUserId::A);
    let simple = SimpleTopology::make(harness::FAST_DELAYS).await;

    // 1. Unlock everything, so each side's lock is a real transition it stamps a date for.
    simple.follower.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &simple.topology, &user).await;

    // 2. Lock the follower while the leader is down, so its lock reaches nobody and it alone stamps
    //    that date. The leader returns as a fresh, locked process with nothing recorded, so its own
    //    lock event stamps the later date — a vault timeout firing just after a restart.
    simple.leader.go_offline();
    simple.follower.manual_lock(user.id).await;
    bitwarden_threading::time::sleep(Duration::from_millis(30)).await;

    // Read the follower's date while the leader is still down: once the two can see each other,
    // the leader's later date can reach the follower at any tick and overwrite it.
    let follower_date = simple
        .follower
        .recorded_date(user.id)
        .expect("The follower recorded its own lock");

    simple.leader.come_online().await;
    simple.leader.manual_lock(user.id).await;

    // 3. Assert the two dates really are different.
    let leader_date = simple
        .leader
        .recorded_date(user.id)
        .expect("The leader recorded its own lock");
    assert_ne!(
        follower_date, leader_date,
        "The two locks should be far enough apart to have different dates"
    );

    // 4. Assert both sides settle on the newest date. They already agree on the state, so only the
    //    date has to travel.
    assert_eq!(
        wait_for_one_recorded_date(&simple.topology, user.id).await,
        follower_date.max(leader_date),
        "The older date should have been replaced, not merely coexisted with"
    );
}

/// A browser extension with no desktop app running: its own syncs go nowhere, but it is still the
/// peer the web vault syncs to.
///
/// ```text
/// web LOCKED --> UNLOCKED
///     |
/// browser LOCKED --> UNLOCKED
///     |
///     x  desktop offline
/// ```
#[tokio::test]
async fn browser_serves_web_without_desktop() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());

    let missing_desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let browser = topology.add_device(
        "browser",
        DeviceOptions::new(ClientType::Browser, &[user.id])
            .following(&missing_desktop)
            .with_vault_url(VAULT_URL),
    );
    let web = topology.add_device(
        "web",
        DeviceOptions::new(ClientType::Web, &[user.id])
            .following(&browser)
            .with_vault_url(VAULT_URL),
    );

    topology.start().await;
    missing_desktop.go_offline();

    // 1. Unlock the web client; all reachable devices must become unlocked. Serving downward is
    //    unaffected by having nowhere to sync upward.
    web.manual_unlock(user.id, &user.key).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;

    // 2. Assert the browser's upward syncs were reported unreachable. They only show up once its
    //    timer fires — applying the web's sync does not itself make the browser send anything.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 2).await;
    assert!(
        count_unreachable(&topology, "browser") > 0,
        "The browser's upward syncs should be reported unreachable"
    );
}
