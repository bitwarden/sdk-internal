use std::sync::{Arc, atomic::Ordering};

use super::TrackerInner;
use crate::traits::Reachability;

/// A scoped reachability subscription for a single endpoint. Holding it keeps that endpoint's
/// reachability fresh; dropping the last handle for an endpoint stops its ping loop.
#[derive(Clone)]
pub struct ReachabilityHandle {
    // Visible to the rest of the `reachability` module so the tracker can construct handles.
    pub(super) inner: Arc<TrackerInner>,
}

impl ReachabilityHandle {
    /// Whether the tracked endpoint is currently reachable.
    ///
    /// Pulls the transport-native signal on demand; only when that is [`Reachability::Unknown`]
    /// does it fall back to the ping/pong liveness signal.
    pub async fn is_reachable(&self) -> bool {
        match (self.inner.reach_fn)(self.inner.endpoint.clone()).await {
            Reachability::Reachable => true,
            Reachability::Unreachable => false,
            // No transport opinion: reachable while a reply was seen within the last ping cycle.
            Reachability::Unknown => self.inner.live.load(Ordering::Relaxed),
        }
    }
}
