//! Assertions over the captured log. Each failure prints everything captured while the topology was
//! alive — the crate's own tracing included — which is what makes a failure diagnosable.

use std::time::Duration;

use bitwarden_core::UserId;
use bitwarden_shared_unlock::LockState;
use bitwarden_threading::time::sleep;
use web_time::Instant;

use super::{
    TestUser,
    device::SimulatedDevice,
    logs::{CapturedEvent, TEST_MANUAL_LOCK, TopologyId, events_for, kind},
    store::LockStateStore,
    topology::SharedUnlockTopology,
};

/// Generous relative to the millisecond timings the tests run at; a scenario that needs the whole
/// budget has genuinely failed to converge rather than merely been slow.
pub(crate) const CONVERGE_TIMEOUT: Duration = Duration::from_secs(10);

fn fail(message: String, topology: &SharedUnlockTopology) -> ! {
    panic!("{message}{}", topology.captured_log());
}

fn describe(state: &LockState) -> &'static str {
    match state {
        LockState::Locked => "locked",
        LockState::Unlocked { .. } => "unlocked",
    }
}

/// Events this topology reported, oldest first.
fn events(topology: TopologyId) -> Vec<CapturedEvent> {
    events_for(topology)
}

/// Every event this topology reported that matches `predicate`, oldest first.
pub(crate) fn events_matching(
    topology: &SharedUnlockTopology,
    predicate: impl Fn(&CapturedEvent) -> bool,
) -> Vec<CapturedEvent> {
    events(topology.id())
        .into_iter()
        .filter(|event| predicate(event))
        .collect()
}

/// The state a scenario expects a user to settle on across the topology.
pub(crate) enum TargetLockState {
    Locked,
    Unlocked,
}

/// Waits until every device that has an account for `user` settles on `target`.
pub(crate) async fn wait_for_devices_reaching_state(
    target: TargetLockState,
    topology: &SharedUnlockTopology,
    user: &TestUser,
) {
    let expected = match target {
        TargetLockState::Locked => user.locked(),
        TargetLockState::Unlocked => user.unlocked(),
    };

    wait_for_topology_reaching_state(topology, user.id, &expected, CONVERGE_TIMEOUT).await;
}

/// Fails unless every device that has an account for `user` is already in `target`. Unlike
/// [`wait_for_devices_reaching_state`] this does not wait, so it states that a change elsewhere
/// left this user alone.
pub(crate) fn assert_user_state(
    target: TargetLockState,
    topology: &SharedUnlockTopology,
    user: &TestUser,
) {
    let expected = match target {
        TargetLockState::Locked => user.locked(),
        TargetLockState::Unlocked => user.unlocked(),
    };

    for (device, store) in devices_holding(topology, user.id) {
        let actual = store.peek(user.id);
        if actual == expected {
            continue;
        }
        fail(
            format!(
                "\"{}\" reports user {} as {}, expected {}",
                device.name(),
                user.id,
                describe(&actual),
                describe(&expected)
            ),
            topology,
        );
    }
}

/// The devices an assertion covers, each paired with the store: booted, and
/// holding an account for `user_id`. Empty means the scenario is asserting nothing, which is always
/// a bug in the scenario.
fn devices_holding(
    topology: &SharedUnlockTopology,
    user_id: UserId,
) -> Vec<(SimulatedDevice, LockStateStore)> {
    let devices: Vec<_> = topology
        .devices()
        .into_iter()
        .filter_map(|device| device.try_store().map(|store| (device, store)))
        .filter(|(_, store)| store.knows(user_id))
        .collect();

    if devices.is_empty() {
        fail(
            format!("No booted device holds user {user_id}, so there is nothing to assert"),
            topology,
        );
    }

    devices
}

/// Waits until every device that has an account for `user_id` reports `expected`.
async fn wait_for_topology_reaching_state(
    topology: &SharedUnlockTopology,
    user_id: UserId,
    expected: &LockState,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let devices = devices_holding(topology, user_id);
        let converged = devices
            .iter()
            .all(|(_, store)| &store.peek(user_id) == expected);
        if converged {
            return;
        }
        if Instant::now() >= deadline {
            let actual = devices
                .iter()
                .map(|(device, store)| {
                    format!("{}={}", device.name(), describe(&store.peek(user_id)))
                })
                .collect::<Vec<_>>()
                .join(", ");
            fail(
                format!(
                    "Timed out after {timeout:?} waiting for user {user_id} to be {} everywhere. \
                     Actual: {actual}",
                    describe(expected)
                ),
                topology,
            );
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until every device holding `user_id` has recorded the same date for it, and returns that
/// date. Agreeing on the state is not enough: the side holding the older date re-advertises it on
/// every tick forever.
pub(crate) async fn wait_for_one_recorded_date(
    topology: &SharedUnlockTopology,
    user_id: UserId,
) -> u64 {
    let deadline = Instant::now() + CONVERGE_TIMEOUT;
    loop {
        let dates: Vec<(String, Option<u64>)> = devices_holding(topology, user_id)
            .iter()
            .map(|(device, _)| (device.name().to_owned(), device.recorded_date(user_id)))
            .collect();

        if let [(_, Some(first)), rest @ ..] = dates.as_slice()
            && rest.iter().all(|(_, date)| date == &Some(*first))
        {
            return *first;
        }

        if Instant::now() >= deadline {
            let actual = dates
                .iter()
                .map(|(name, date)| format!("{name}={date:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            fail(
                format!(
                    "Timed out after {CONVERGE_TIMEOUT:?} waiting for one recorded date for user \
                     {user_id}. Actual: {actual}"
                ),
                topology,
            );
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// Fails if any device locked a user within `grace` of unlocking it, unless the test asked for that
/// lock — meaning a `ManualLock` device event for the same user was reported anywhere in the
/// topology between the unlock and the lock.
pub(crate) fn assert_no_lock(
    topology: &SharedUnlockTopology,
    user_id: UserId,
    grace: Duration,
    since_ms: u128,
) {
    let wanted = user_id.to_string();
    let for_user: Vec<_> = events(topology.id())
        .into_iter()
        .filter(|event| event.user_id() == Some(wanted.as_str()))
        .collect();

    let requested_locks: Vec<u128> = for_user
        .iter()
        .filter(|event| {
            event.kind() == Some(kind::DEVICE_EVENT)
                && event.field("detail") == Some(TEST_MANUAL_LOCK)
        })
        .map(|event| event.at)
        .collect();

    let grace_ms = grace.as_millis();
    let mut offences = Vec::new();

    for unlock in for_user
        .iter()
        .filter(|event| event.kind() == Some(kind::UNLOCK_START) && event.at >= since_ms)
    {
        let Some(relock) = for_user.iter().find(|event| {
            event.kind() == Some(kind::LOCK_START)
                && event.device() == unlock.device()
                && event.at > unlock.at
        }) else {
            continue;
        };
        if relock.at - unlock.at > grace_ms {
            continue;
        }
        if requested_locks
            .iter()
            .any(|at| *at >= unlock.at && *at <= relock.at)
        {
            continue;
        }
        offences.push(format!(
            "\"{}\" unlocked at {}ms ({}) and was locked again {}ms later at {}ms ({}) with no \
             manual lock in between",
            unlock.device(),
            unlock.at,
            unlock.field("detail").unwrap_or("-"),
            relock.at - unlock.at,
            relock.at,
            relock.field("detail").unwrap_or("-"),
        ));
    }

    if !offences.is_empty() {
        fail(
            format!(
                "Spurious relock of user {user_id} within {grace_ms}ms:\n  {}",
                offences.join("\n  ")
            ),
            topology,
        );
    }
}

/// Fails if a device stopped receiving syncs from its leader, which is what a peer whose receive
/// loop has broken looks like. Separates "the peer went deaf and locked on its own" from "the peer
/// above told it to lock".
pub(crate) fn assert_still_responsive(
    topology: &SharedUnlockTopology,
    device: &str,
    since_ms: u128,
) {
    let seen = events(topology.id()).into_iter().any(|event| {
        event.device() == device
            && event.kind() == Some(kind::SUPPRESS_TIMEOUT)
            && event.at >= since_ms
    });
    if !seen {
        fail(
            format!(
                "\"{device}\" received no sync from its leader after {since_ms}ms — its receive \
                 loop is no longer handling incoming syncs"
            ),
            topology,
        );
    }
}

/// How many sends from `device` failed because their destination was not reachable.
pub(crate) fn count_unreachable(topology: &SharedUnlockTopology, device: &str) -> usize {
    events(topology.id())
        .into_iter()
        .filter(|event| event.device() == device && event.kind() == Some(kind::IPC_UNREACHABLE))
        .count()
}
