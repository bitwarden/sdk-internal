//! Behaviours real clients exhibit that the plain protocol does not model.

use crate::prelude::*;

#[tokio::test]
async fn replaying_a_protocol_lock_as_a_manual_lock_changes_nothing() {
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

    follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    // Locking on the leader propagates down, and the follower reports that lock back into its
    // own peer as if the user had locked it locally. The peer already recorded the lock
    // when it applied it, so the replay must not disturb anything.
    leader.manual_lock(user.id).await;
    wait_for_topology_reaching_state(
        &topology,
        user.id,
        &user.to_locked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;
    bitwarden_threading::time::sleep(grace(&topology)).await;

    let replays = events_matching(&topology, |event| {
        event.field("detail") == Some(REPLAYED_MANUAL_LOCK)
    });
    assert!(
        !replays.is_empty(),
        "The quirk should have replayed the lock"
    );
    assert_eq!(replays[0].device(), "browser");

    // Everything is still locked, and nothing bounced back to unlocked.
    assert_eq!(leader.store().peek(user.id), user.to_locked_lock_state());
    assert_eq!(follower.store().peek(user.id), user.to_locked_lock_state());
}

#[tokio::test]
async fn a_client_that_reloads_after_every_lock_still_converges() {
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

    follower.manual_unlock(user.id, &user.key).await;
    wait_for_topology_reaching_state(
        &topology,
        user.id,
        &user.to_unlocked_lock_state(),
        CONVERGE_TIMEOUT,
    )
    .await;

    leader.manual_lock(user.id).await;

    // Wait for the reload to finish rather than sleeping a fixed amount: these tests share a
    // runtime, so when the quirk fires varies.
    wait_for_event(
        &topology,
        "the browser's process reload to complete",
        CONVERGE_TIMEOUT,
        |event| {
            event.kind() == Some(kind::RELOAD)
                && event.field("detail") == Some("process reload complete")
        },
    )
    .await;
    // Then give it several ticks to prove it does not reload again.
    bitwarden_threading::time::sleep(fast_timing().sync_interval * 6).await;

    let reloads: Vec<String> = events_matching(&topology, |event| {
        event.kind() == Some(kind::RELOAD) && event.device() == "browser"
    })
    .into_iter()
    .map(|event| event.field("detail").unwrap_or_default().to_owned())
    .collect();
    assert_eq!(
        reloads,
        vec!["process reload starting", "process reload complete"],
        "The quirk should have reloaded the process exactly once"
    );

    // The reloaded process is a fresh one, wired up and locked, and the leader agrees.
    assert!(follower.has_peer());
    assert_eq!(follower.store().peek(user.id), user.to_locked_lock_state());
    assert_eq!(leader.store().peek(user.id), user.to_locked_lock_state());
}
