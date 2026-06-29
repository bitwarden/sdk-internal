use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use super::{PING_INTERVAL, POLL_INTERVAL, ReachFn, Registry, SendFn, prune};
use crate::{control::ControlMessage, endpoint::Endpoint, traits::Reachability};

/// A scoped reachability subscription for a single endpoint. Holding it keeps that endpoint's
/// reachability fresh; dropping the last handle for an endpoint stops its ping loop.
#[derive(Clone)]
pub struct ReachabilityHandle {
    // Visible to the rest of the `reachability` module so the tracker can construct handles.
    pub(super) inner: Arc<ReachabilityHandleInner>,
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

/// Shared per-endpoint state behind one or more [`ReachabilityHandle`]s. It owns the endpoint's
/// ping loop (spawned in [`spawn_loop`](Self::spawn_loop)); the loop holds only a [`Weak`] to this,
/// so dropping the last handle ends the loop and (via [`Drop`]) prunes the registry entry.
pub(super) struct ReachabilityHandleInner {
    endpoint: Endpoint,
    /// Whether the endpoint is currently live per ping/pong. Only consulted when the transport
    /// answers `Unknown`. Set as soon as a control frame is seen; cleared by the ping loop after a
    /// cycle with no reply.
    live: AtomicBool,
    /// Set whenever a control frame is seen from `endpoint`; the ping loop clears it before each
    /// ping and reads it after the interval to detect a missed reply.
    reply_seen: AtomicBool,
    send_fn: SendFn,
    reach_fn: ReachFn,
    /// Back-ref so this entry can remove itself from the owning tracker's registry on drop.
    registry: Weak<Registry>,
}

impl ReachabilityHandleInner {
    pub(super) fn new(
        endpoint: Endpoint,
        send_fn: SendFn,
        reach_fn: ReachFn,
        registry: Weak<Registry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            live: AtomicBool::new(false),
            reply_seen: AtomicBool::new(false),
            send_fn,
            reach_fn,
            registry,
        })
    }

    /// Record that a control frame was just seen from this endpoint: it is alive now, and the
    /// in-flight ping cycle should not clear liveness.
    pub(super) fn mark_alive(&self) {
        self.live.store(true, Ordering::Relaxed);
        self.reply_seen.store(true, Ordering::Relaxed);
    }

    /// Spawn this endpoint's ping loop. The loop holds only a [`Weak`] to `self`, so it ends once
    /// the last handle is dropped (the upgrade then fails). The strong ref is released before each
    /// sleep so a drop during the sleep is observed on the next cycle.
    pub(super) fn spawn_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let future = async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    break;
                };

                let reachability = (inner.reach_fn)(inner.endpoint.clone()).await;
                let interval = if reachability == Reachability::Unknown {
                    // Probe: clear the reply flag, ping, and let the interval act as the window in
                    // which a reply must arrive.
                    inner.reply_seen.store(false, Ordering::Relaxed);
                    (inner.send_fn)(ControlMessage::Ping.to_outgoing(inner.endpoint.clone())).await;
                    PING_INTERVAL
                } else {
                    // The transport answered authoritatively; no ping needed. Keep polling at the
                    // backoff cadence so a later transition to `Unknown` resumes pinging.
                    POLL_INTERVAL
                };

                drop(inner);
                bitwarden_threading::time::sleep(interval).await;

                // After the probe window, if no reply was seen the endpoint is no longer live. A
                // reply (see `mark_alive`) sets `live` immediately, so liveness is not delayed by
                // this cycle.
                if reachability == Reachability::Unknown {
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    if !inner.reply_seen.load(Ordering::Relaxed) {
                        inner.live.store(false, Ordering::Relaxed);
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
    }
}

impl Drop for ReachabilityHandleInner {
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
