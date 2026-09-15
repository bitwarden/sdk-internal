//! The shared-unlock protocol test suite.

mod harness;

mod scenarios;

/// What every scenario module needs. Grouped so each file opens with a single `use`.
mod prelude {
    pub(crate) use std::time::Duration;

    pub(crate) use super::{VAULT_URL, grace, harness};
    pub(crate) use crate::harness::{
        CONVERGE_TIMEOUT, ClientType, DeviceOptions, DeviceQuirks, REPLAYED_MANUAL_LOCK,
        SLOW_DELAYS, SharedUnlockTopology, SimpleTopology, TargetLockState, TestUserId,
        assert_no_lock, assert_still_responsive, assert_user_state, count_unreachable,
        events_matching, fast_timing, kind, test_user, wait_for_devices_reaching_state,
        wait_for_event,
    };
}

use std::time::Duration;

use harness::SharedUnlockTopology;

const VAULT_URL: &str = "https://vault.example.com";

/// How long to wait for a state that should *not* change, long enough that a stale advertisement
/// would have had several ticks to undo it.
fn grace(topology: &SharedUnlockTopology) -> Duration {
    let _ = topology;
    Duration::from_millis(400)
}
