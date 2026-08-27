//! How often a peer syncs, and the clock its dates come from.

use std::time::Duration;

use crate::{PEER_STALE_AFTER, SYNC_INTERVAL, VAULT_TIMEOUT_GRACE_PERIOD};

/// How often a peer syncs, and how long it tolerates silence from another peer.
///
/// Separated out from the constants so tests can run the protocol on millisecond timings rather
/// than waiting out the multi-second production ones. Not part of the public API: every real client
/// uses [`SharedUnlockTiming::default`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct SharedUnlockTiming {
    pub(crate) sync_interval: Duration,
    pub(crate) vault_timeout_grace_period: Duration,
    pub(crate) peer_stale_after: Duration,
}

impl Default for SharedUnlockTiming {
    fn default() -> Self {
        Self {
            sync_interval: SYNC_INTERVAL,
            vault_timeout_grace_period: VAULT_TIMEOUT_GRACE_PERIOD,
            peer_stale_after: PEER_STALE_AFTER,
        }
    }
}

/// Milliseconds since the Unix epoch. `web_time` re-exports `std::time` off wasm, so this is the
/// same clock on every target.
pub(crate) fn now_millis() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
