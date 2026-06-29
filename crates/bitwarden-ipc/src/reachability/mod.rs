//! Reachability tracking: a transport-authoritative signal with a ping/pong liveness fallback.
//!
//! A consumer that cares whether a peer is reachable (e.g. the shared-unlock follower) obtains a
//! [`ReachabilityHandle`] from [`ReachabilityTracker::track`] *after* it knows the peer's endpoint.
//! While a handle is held, that endpoint's reachability is kept fresh; when the last handle for an
//! endpoint is dropped the per-endpoint ping loop stops on its own.
//!
//! Reachability resolves as follows:
//! - the transport answers [`Reachability::Reachable`]/[`Reachability::Unreachable`] -> that wins,
//!   and no pings are sent;
//! - the transport answers [`Reachability::Unsupported`] -> fall back to ping/pong liveness: the
//!   endpoint is reachable while replies to its pings keep arriving (see [`PING_INTERVAL`]).
//!
//! Ping/pong frames travel over the raw transport under a reserved control-topic namespace and are
//! peeled off by the [`ControlSplitter`](crate::control_splitter::ControlSplitter) before the
//! crypto layer ever sees them, so they never abort a handshake.
//!
//! Layout: [`ReachabilityHandle`] and its shared inner (which owns the ping loop) live in `handle`;
//! the [`ReachabilityTracker`] that hands out and routes to handles lives in `tracker`.

mod handle;
mod tracker;

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

pub use handle::ReachabilityHandle;
pub use tracker::ReachabilityTracker;

use self::handle::ReachabilityHandleInner;
use crate::{endpoint::Endpoint, message::OutgoingMessage, traits::Reachability};

/// Ping cadence while probing an endpoint whose transport is `Unsupported`. Each cycle sends a ping
/// and, after this interval, marks the endpoint not-live unless a reply was seen — so it doubles as
/// the liveness window. Kept clock-free (sleep-based) so it works on wasm too.
const PING_INTERVAL: Duration = Duration::from_secs(2);

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Type-erased "send this frame over the raw transport".
type SendFn = Arc<dyn Fn(OutgoingMessage) -> BoxFuture<()> + Send + Sync>;
/// Type-erased "ask the transport whether this endpoint is reachable".
type ReachFn = Arc<dyn Fn(Endpoint) -> BoxFuture<Reachability> + Send + Sync>;

/// Maps each tracked endpoint to its shared handle state. Used both to dedup handles (one inner,
/// one ping loop per endpoint) and to route inbound control frames to the right endpoint's state.
type Registry = Mutex<HashMap<Endpoint, Weak<ReachabilityHandleInner>>>;

/// Remove registry entries whose handles have all been dropped (dangling weaks), keeping the map
/// bounded to currently-tracked endpoints. Safe to call at any time: a concurrently-recreated entry
/// for the same endpoint has a strong count >= 1 and is preserved.
fn prune(registry: &mut HashMap<Endpoint, Weak<ReachabilityHandleInner>>) {
    registry.retain(|_, weak| weak.strong_count() > 0);
}
