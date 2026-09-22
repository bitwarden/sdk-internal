//! The shared-unlock protocol test suite.

mod harness;

mod scenarios;

/// What every scenario module needs. Grouped so each file opens with a single `use`.
mod prelude {
    pub(crate) use std::time::Duration;

    pub(crate) use super::{VAULT_URL, harness};
    pub(crate) use crate::harness::{
        ClientType, DeviceOptions, DeviceQuirks, GRACE, REPLAYED_MANUAL_LOCK, SLOW_DELAYS,
        SharedUnlockTopology, SimpleTopology, TargetLockState, TestUserId, assert_no_lock,
        assert_still_responsive, assert_user_state, count_unreachable, events_matching,
        fast_timing, test_user, wait_for_devices_reaching_state, wait_for_one_recorded_date,
    };
}

const VAULT_URL: &str = "https://vault.example.com";
