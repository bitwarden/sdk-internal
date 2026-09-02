//! The shared-unlock protocol test suite.

mod harness;

mod scenarios;

/// What every scenario module needs. Grouped so each file opens with a single `use`.
mod prelude {
    pub(crate) use std::time::Duration;

    pub(crate) use super::{CONVERGE_TIMEOUT, VAULT_URL, grace, harness};
    pub(crate) use crate::harness::{
        ClientType, DeviceOptions, DeviceQuirks, REPLAYED_MANUAL_LOCK, SLOW_DELAYS,
        SharedUnlockTopology, SimpleTopology, TestUserId, assert_no_lock, assert_still_responsive,
        count_unreachable, events_matching, fast_timing, kind, test_user,
        wait_for_device_reaching_state, wait_for_event, wait_for_topology_reaching_state,
    };
}

use std::time::Duration;

use harness::SharedUnlockTopology;

const VAULT_URL: &str = "https://vault.example.com";

/// Generous relative to the millisecond timings the tests run at; a scenario that needs the whole
/// budget has genuinely failed to converge rather than merely been slow.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a state that should *not* change, long enough that a stale advertisement
/// would have had several ticks to undo it.
fn grace(topology: &SharedUnlockTopology) -> Duration {
    let _ = topology;
    Duration::from_millis(400)
}
