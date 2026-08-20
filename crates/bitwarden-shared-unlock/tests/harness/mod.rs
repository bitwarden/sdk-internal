//! Scenario harness for the shared-unlock protocol.
//!
//! Models a topology of [`SimulatedDevice`]s on an endpoint-routed [`InMemoryIpcTransport`]
//! carrying real Noise sessions, and observes what happened through the `tracing` output both it
//! and the crate under test emit. Each device runs one real [`SharedUnlockPeer`] with its real
//! receive loop and sync timer, so what is under test is the protocol as it actually runs, not a
//! hand-pumped approximation of it.
//!
//! Timings come from [`Timing`], which the tests set to milliseconds; otherwise every wait here
//! would be a production-length 5s tick.
//!
//! # Seeing the logs
//!
//! Nothing is printed unless `RUST_LOG` asks for it; a failing assertion prints the captured log by
//! itself. To watch a run live, name a single test — the tests run concurrently, so with more than
//! one in flight the lines interleave and only the `topology` field tells them apart:
//!
//! ```text
//! RUST_LOG=debug cargo test -p bitwarden-shared-unlock \
//!     --test shared_unlock simple_topology::unlock_from_a_follower_reaches_its_leader -- --nocapture
//! ```
//!
//! Filter by target to narrow it down: `bitwarden_shared_unlock=debug` for the protocol's own
//! tracing only, `shared_unlock_harness=debug` for what the simulated devices did only.

mod assertions;
mod client_type;
mod device;
mod in_memory_ipc_transport;
mod logs;
mod store;
mod topology;

use std::time::Duration;

pub(crate) use assertions::*;
use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_encoding::B64;
use bitwarden_shared_unlock::LockState;
pub(crate) use client_type::ClientType;
pub(crate) use device::{DeviceOptions, DeviceQuirks, SimulatedDevice};
pub(crate) use logs::{REPLAYED_MANUAL_LOCK, kind, now_ms};
pub(crate) use store::LockDelays;
pub(crate) use topology::{SharedUnlockTopology, SimpleTopology};

/// Timing profile for tests where lock settling is not the thing under test.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    pub(crate) sync_interval: Duration,
    pub(crate) vault_timeout_grace_period: Duration,
    pub(crate) peer_stale_after: Duration,
}

pub(crate) fn fast_timing() -> Timing {
    Timing {
        sync_interval: Duration::from_millis(50),
        vault_timeout_grace_period: Duration::from_millis(20),
        peer_stale_after: Duration::from_millis(300),
    }
}

/// Settling times short enough that they are not what a test is waiting on.
pub(crate) const FAST_DELAYS: LockDelays = LockDelays {
    lock: Duration::from_millis(10),
    unlock: Duration::from_millis(10),
};

/// Settling times long enough to overlap several sync intervals, for the scenarios that are about a
/// lock which has not finished settling yet.
pub(crate) const SLOW_DELAYS: LockDelays = LockDelays {
    lock: Duration::from_millis(200),
    unlock: Duration::from_millis(200),
};

/// Which of the shared test users a scenario is acting on. Which one only matters when a test
/// needs two accounts to stay independent, or one the leader has no account for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestUserId {
    A,
    B,
    C,
}

/// A test user: its id, and the user key its vault unlocks with. The two always travel together so
/// that no scenario has to keep them in step by hand.
#[derive(Clone)]
pub(crate) struct TestUser {
    pub(crate) id: UserId,
    pub(crate) key: SymmetricCryptoKey,
}

impl TestUser {
    /// The state this user is in when its vault is locked.
    pub(crate) fn to_locked_lock_state(&self) -> LockState {
        LockState::Locked
    }

    /// The state this user is in when its vault is unlocked with its own key.
    pub(crate) fn to_unlocked_lock_state(&self) -> LockState {
        LockState::Unlocked {
            user_key: self.key.clone(),
        }
    }
}

pub(crate) fn test_user(user: TestUserId) -> TestUser {
    let nth: u8 = match user {
        TestUserId::A => 1,
        TestUserId::B => 2,
        TestUserId::C => 3,
    };

    TestUser {
        id: format!("00000000-0000-0000-0000-0000000000{nth:02}")
            .parse()
            .expect("Should be a valid user id"),
        key: SymmetricCryptoKey::try_from(B64::from([nth * 0x11; 64].to_vec()))
            .expect("A 64-byte key should be valid"),
    }
}
