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
//!   endpoint is reachable while a control frame was seen from it within [`ACTIVE_WINDOW`].
//!
//! Ping/pong frames travel over the raw transport under a reserved control-topic namespace and are
//! peeled off by the `ControlSplitter` before the crypto layer ever sees them, so they never abort
//! a handshake.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use web_time::Instant;

use crate::{
    control::{CONTROL_PING_TOPIC, CONTROL_PONG_TOPIC},
    endpoint::Endpoint,
    message::{IncomingMessage, OutgoingMessage},
    traits::{CommunicationBackend, Reachability},
};

/// An endpoint is considered live (when the transport can't tell) while a control frame was seen
/// from it within this window.
const ACTIVE_WINDOW: Duration = Duration::from_secs(5);
/// Ping cadence while the peer is live. Must be `< ACTIVE_WINDOW` to sustain liveness.
const ACTIVE_PING_INTERVAL: Duration = Duration::from_secs(2);
/// Ping/poll cadence while the peer is not live (or the transport answers authoritatively).
const INACTIVE_PING_INTERVAL: Duration = Duration::from_secs(10);

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
    /// Timestamp of the last control frame seen from `endpoint`; the liveness fallback derives
    /// from it when the transport answers `Unknown`.
    last_seen: Mutex<Option<Instant>>,
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

/// A scoped reachability subscription for a single endpoint. Holding it keeps that endpoint's
/// reachability fresh; dropping the last handle for an endpoint stops its ping loop.
#[derive(Clone)]
pub struct ReachabilityHandle {
    inner: Arc<TrackerInner>,
}

impl ReachabilityHandle {
    /// Whether the tracked endpoint is currently reachable.
    ///
    /// Pulls the transport-native signal on demand; only when that is [`Reachability::Unknown`]
    /// does it fall back to the ping/pong liveness window.
    pub async fn is_reachable(&self) -> bool {
        match (self.inner.reach_fn)(self.inner.endpoint.clone()).await {
            Reachability::Reachable => true,
            Reachability::Unreachable => false,
            Reachability::Unknown => self.is_live(),
        }
    }

    /// Raw ping/pong liveness: whether a control frame was seen within [`ACTIVE_WINDOW`].
    fn is_live(&self) -> bool {
        within_window(
            *self
                .inner
                .last_seen
                .lock()
                .expect("reachability last_seen mutex poisoned"),
            ACTIVE_WINDOW,
        )
    }
}

/// Tracks whether peer endpoints are reachable, so a caller can avoid sending to an absent peer.
///
/// Obtain one from [`IpcClient::reachability`](crate::IpcClient::reachability) and call
/// [`track`](Self::track) with a peer's endpoint to get a [`ReachabilityHandle`]; query the handle
/// with [`ReachabilityHandle::is_reachable`]. A handle is a live subscription — hold it for as long
/// as you care about the endpoint and drop it to stop tracking.
///
/// Reachability is resolved by asking the transport first ([`Reachability::Reachable`] /
/// [`Reachability::Unreachable`] are taken at face value); only when the transport answers
/// [`Reachability::Unknown`] does the tracker fall back to a ping/pong liveness window, emitting
/// pings to that endpoint and treating it as reachable while a reply was seen recently.
pub struct ReachabilityTracker {
    registry: Arc<Registry>,
    send_fn: SendFn,
    reach_fn: ReachFn,
}

impl ReachabilityTracker {
    /// Build a tracker over `backend`, capturing it for sending pings/pongs and pulling the
    /// transport-native reachability signal.
    pub(crate) fn from_backend<Com: CommunicationBackend>(backend: Arc<Com>) -> Self {
        let send_backend = backend.clone();
        let send_fn: SendFn = Arc::new(move |message| {
            let backend = send_backend.clone();
            Box::pin(async move {
                let _ = backend.send(message).await;
            })
        });
        let reach_fn: ReachFn = Arc::new(move |endpoint| {
            let backend = backend.clone();
            Box::pin(async move { backend.reachability(&endpoint).await })
        });
        Self::new(send_fn, reach_fn)
    }

    fn new(send_fn: SendFn, reach_fn: ReachFn) -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            send_fn,
            reach_fn,
        }
    }

    /// Begin (or join) tracking `endpoint`, returning a handle. Calls for the same endpoint share a
    /// single ping loop; the loop is spawned only when the first handle for an endpoint is created.
    pub fn track(&self, endpoint: Endpoint) -> ReachabilityHandle {
        let mut map = self
            .registry
            .lock()
            .expect("reachability registry poisoned");
        // Opportunistically drop dangling entries left by handles that have since been freed.
        prune(&mut map);

        if let Some(inner) = map.get(&endpoint).and_then(Weak::upgrade) {
            return ReachabilityHandle { inner };
        }

        let inner = Arc::new(TrackerInner {
            endpoint: endpoint.clone(),
            last_seen: Mutex::new(None),
            reach_fn: self.reach_fn.clone(),
            registry: Arc::downgrade(&self.registry),
        });
        map.insert(endpoint.clone(), Arc::downgrade(&inner));

        spawn_ping_loop(
            Arc::downgrade(&inner),
            self.send_fn.clone(),
            self.reach_fn.clone(),
            endpoint,
        );

        ReachabilityHandle { inner }
    }

    /// Process an inbound control frame: record liveness for the source (if it is tracked) and, for
    /// a ping, answer with a pong. Called by the `ControlSplitter`.
    pub async fn handle_inbound(&self, message: IncomingMessage) {
        let source = message.source.to_endpoint();

        if let Some(inner) = self
            .registry
            .lock()
            .expect("reachability registry poisoned")
            .get(&source)
            .and_then(Weak::upgrade)
        {
            *inner
                .last_seen
                .lock()
                .expect("reachability last_seen mutex poisoned") = Some(Instant::now());
        }

        if message.topic.as_deref() == Some(CONTROL_PING_TOPIC) {
            (self.send_fn)(OutgoingMessage {
                payload: Vec::new(),
                destination: source,
                topic: Some(CONTROL_PONG_TOPIC.to_owned()),
            })
            .await;
        }
    }
}

/// `true` when `last` is set and within `window` of now.
fn within_window(last: Option<Instant>, window: Duration) -> bool {
    matches!(last, Some(at) if at.elapsed() < window)
}

fn spawn_ping_loop(
    inner: Weak<TrackerInner>,
    send_fn: SendFn,
    reach_fn: ReachFn,
    endpoint: Endpoint,
) {
    let future = async move {
        loop {
            // The loop holds only a `Weak`; once the last handle is dropped this upgrade fails and
            // the loop ends. The strong ref is released again before sleeping so a drop during the
            // sleep is observed on the next cycle.
            let Some(inner) = inner.upgrade() else {
                break;
            };

            let interval = match (reach_fn)(endpoint.clone()).await {
                Reachability::Unknown => {
                    (send_fn)(OutgoingMessage {
                        payload: Vec::new(),
                        destination: endpoint.clone(),
                        topic: Some(CONTROL_PING_TOPIC.to_owned()),
                    })
                    .await;

                    let live = within_window(
                        *inner
                            .last_seen
                            .lock()
                            .expect("reachability last_seen mutex poisoned"),
                        ACTIVE_WINDOW,
                    );
                    if live {
                        ACTIVE_PING_INTERVAL
                    } else {
                        INACTIVE_PING_INTERVAL
                    }
                }
                // The transport answered authoritatively; no ping needed. Keep polling at the
                // backoff cadence so a later transition to `Unknown` resumes pinging.
                Reachability::Reachable | Reachability::Unreachable => INACTIVE_PING_INTERVAL,
            };

            drop(inner);
            bitwarden_threading::time::sleep(interval).await;
        }
    };

    #[cfg(not(target_arch = "wasm32"))]
    tokio::spawn(future);
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(future);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{HostId, Source};

    const ENDPOINT: Endpoint = Endpoint::DesktopMain;

    /// Builds a tracker whose transport answers `reach` and records every outgoing frame.
    fn mock_tracker(
        reach: Reachability,
    ) -> (ReachabilityTracker, Arc<Mutex<Vec<OutgoingMessage>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = sent.clone();
        let send_fn: SendFn = Arc::new(move |message| {
            let sent = sent_clone.clone();
            Box::pin(async move {
                sent.lock().unwrap().push(message);
            })
        });
        let reach_fn: ReachFn = Arc::new(move |_| Box::pin(async move { reach }));
        (ReachabilityTracker::new(send_fn, reach_fn), sent)
    }

    fn incoming(source: Source, topic: Option<&str>) -> IncomingMessage {
        IncomingMessage {
            payload: Vec::new(),
            destination: ENDPOINT,
            source,
            topic: topic.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn within_window_boundary() {
        assert!(within_window(Some(Instant::now()), ACTIVE_WINDOW));
        assert!(!within_window(None, ACTIVE_WINDOW));
        assert!(!within_window(
            Some(Instant::now() - (ACTIVE_WINDOW + Duration::from_secs(1))),
            ACTIVE_WINDOW
        ));
    }

    #[tokio::test]
    async fn transport_answer_wins_without_pinging() {
        for (reach, expected) in [
            (Reachability::Reachable, true),
            (Reachability::Unreachable, false),
        ] {
            let (tracker, _sent) = mock_tracker(reach);
            let handle = tracker.track(ENDPOINT);
            assert_eq!(handle.is_reachable().await, expected);
        }
    }

    #[tokio::test]
    async fn unknown_falls_back_to_liveness_window() {
        let (tracker, _sent) = mock_tracker(Reachability::Unknown);
        let handle = tracker.track(ENDPOINT);

        // No control frame seen yet -> not reachable.
        assert!(!handle.is_reachable().await);

        // An inbound control frame from the tracked endpoint marks it live.
        tracker
            .handle_inbound(incoming(Source::DesktopMain, Some(CONTROL_PONG_TOPIC)))
            .await;
        assert!(handle.is_reachable().await);
    }

    #[tokio::test]
    async fn answers_inbound_ping_with_pong() {
        let (tracker, sent) = mock_tracker(Reachability::Unknown);
        let web = Source::Web {
            tab_id: 7,
            document_id: "doc".to_owned(),
            origin: "https://example.com".to_owned(),
        };

        tracker
            .handle_inbound(incoming(web, Some(CONTROL_PING_TOPIC)))
            .await;

        let sent = sent.lock().unwrap();
        assert!(sent.iter().any(|m| {
            m.topic.as_deref() == Some(CONTROL_PONG_TOPIC)
                && m.destination
                    == (Endpoint::Web {
                        tab_id: 7,
                        document_id: "doc".to_owned(),
                    })
        }));
    }

    #[tokio::test]
    async fn track_dedupes_by_endpoint() {
        let (tracker, _sent) = mock_tracker(Reachability::Unknown);
        let handle_a = tracker.track(ENDPOINT);
        let handle_b = tracker.track(ENDPOINT);

        // Same shared inner -> a single ping loop, one registry entry.
        assert!(Arc::ptr_eq(&handle_a.inner, &handle_b.inner));
        assert_eq!(tracker.registry.lock().unwrap().len(), 1);

        // A different endpoint gets its own entry.
        let _handle_c = tracker.track(Endpoint::BrowserBackground { id: HostId::Own });
        assert_eq!(tracker.registry.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn dropping_last_handle_cleans_registry_entry() {
        let (tracker, _sent) = mock_tracker(Reachability::Unknown);
        let handle_a = tracker.track(ENDPOINT);
        let handle_b = tracker.track(ENDPOINT);
        assert_eq!(tracker.registry.lock().unwrap().len(), 1);

        drop(handle_a);
        // One handle still alive -> entry retained.
        assert_eq!(tracker.registry.lock().unwrap().len(), 1);

        drop(handle_b);
        // Last handle gone -> Drop removed the entry.
        assert_eq!(tracker.registry.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn pings_only_when_transport_is_unknown() {
        // Unknown -> the loop emits at least one ping promptly.
        let (tracker, sent) = mock_tracker(Reachability::Unknown);
        let _handle = tracker.track(ENDPOINT);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            sent.lock()
                .unwrap()
                .iter()
                .any(|m| m.topic.as_deref() == Some(CONTROL_PING_TOPIC)),
            "an Unknown transport should be probed with a ping"
        );

        // Reachable -> no pings.
        let (tracker, sent) = mock_tracker(Reachability::Reachable);
        let _handle = tracker.track(ENDPOINT);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            sent.lock().unwrap().is_empty(),
            "an authoritative transport answer should not be pinged"
        );
    }

    #[tokio::test]
    async fn ping_loop_stops_after_last_handle_dropped() {
        let (tracker, sent) = mock_tracker(Reachability::Unknown);
        let handle = tracker.track(ENDPOINT);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(handle);
        // Allow the loop to observe the drop and stop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let count_after_drop = sent.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            sent.lock().unwrap().len(),
            count_after_drop,
            "no further pings should be emitted once the loop has stopped"
        );
    }
}
