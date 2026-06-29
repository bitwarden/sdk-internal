//! Reachability tracking: a transport-authoritative signal with a ping/pong liveness fallback.
//!
//! A consumer that cares whether a peer is reachable (e.g. the shared-unlock follower) obtains a
//! [`ReachabilityHandle`] from [`ReachabilityTracker::track`] *after* it knows the peer's endpoint.
//! While a handle is held, the tracker keeps that endpoint's reachability fresh; when the last
//! handle for an endpoint is dropped the per-endpoint ping loop stops on its own.
//!
//! Reachability resolves as follows:
//! - the transport answers [`Reachability::Reachable`]/[`Reachability::Unreachable`] -> that wins,
//!   and no pings are sent;
//! - the transport answers [`Reachability::Unknown`] -> fall back to ping/pong liveness: the
//!   endpoint is reachable while replies to its pings keep arriving (see [`PING_INTERVAL`]).
//!
//! Ping/pong frames travel over the raw transport under a reserved control-topic namespace and are
//! peeled off by the [`ControlSplitter`](crate::control_splitter::ControlSplitter) before the
//! crypto layer ever sees them, so they never abort a handshake.

mod handle;
mod tracker;

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak, atomic::AtomicBool},
    time::Duration,
};

pub use handle::ReachabilityHandle;
pub use tracker::ReachabilityTracker;

use crate::{endpoint::Endpoint, message::OutgoingMessage, traits::Reachability};

/// Ping cadence while probing an endpoint whose transport reachability is `Unknown`. Each cycle
/// sends a ping and, after this interval, marks the endpoint not-live unless a reply was seen — so
/// it doubles as the liveness window. Kept clock-free (sleep-based) so it works on wasm too.
const PING_INTERVAL: Duration = Duration::from_secs(2);
/// Re-check cadence while the transport answers authoritatively (no pinging needed).
const POLL_INTERVAL: Duration = Duration::from_secs(10);

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Type-erased "send this frame over the raw transport".
type SendFn = Arc<dyn Fn(OutgoingMessage) -> BoxFuture<()> + Send + Sync>;
/// Type-erased "ask the transport whether this endpoint is reachable".
type ReachFn = Arc<dyn Fn(Endpoint) -> BoxFuture<Reachability> + Send + Sync>;

type Registry = Mutex<HashMap<Endpoint, Weak<TrackerInner>>>;

/// Remove registry entries whose handles have all been dropped (dangling weaks), keeping the map
/// bounded to currently-tracked endpoints. Safe to call at any time: a concurrently-recreated entry
/// for the same endpoint has a strong count >= 1 and is preserved.
fn prune(registry: &mut HashMap<Endpoint, Weak<TrackerInner>>) {
    registry.retain(|_, weak| weak.strong_count() > 0);
}

/// Per-endpoint tracking state, shared between the [`ReachabilityHandle`]s for that endpoint and
/// (via a [`Weak`]) the ping loop. Dropping the last handle drops this, which both ends the loop
/// (its weak upgrade fails) and removes the registry entry (see [`Drop`]).
struct TrackerInner {
    endpoint: Endpoint,
    /// Whether the endpoint is currently live per ping/pong. Only consulted when the transport
    /// answers `Unknown`. Set as soon as a control frame is seen; cleared by the ping loop after a
    /// cycle with no reply.
    live: AtomicBool,
    /// Set whenever a control frame is seen from `endpoint`; the ping loop clears it before each
    /// ping and reads it after the interval to detect a missed reply.
    reply_seen: AtomicBool,
    reach_fn: ReachFn,
    /// Back-ref so this entry can remove itself from the owning tracker's registry on drop.
    registry: Weak<Registry>,
}

impl Drop for TrackerInner {
    fn drop(&mut self) {
        // Bound the registry to live entries. Removing by `retain(strong > 0)` rather than by key
        // is race-safe: if a concurrent `track()` already replaced our (now-dead) entry with a new
        // live one, that new entry has a strong count >= 1 and is preserved.
        if let Some(registry) = self.registry.upgrade()
            && let Ok(mut map) = registry.lock()
        {
            prune(&mut map);
        }
    }
}
