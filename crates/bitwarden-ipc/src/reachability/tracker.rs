use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::select;

use super::{
    ReachFn, Registry, SendFn,
    handle::{ReachabilityHandle, ReachabilityHandleInner},
    prune,
};
use crate::{
    control::{ControlMessage, IncomingControlMessage},
    control_splitter::ControlReceiver,
    endpoint::Endpoint,
    error::IpcErrorKind,
    traits::{CommunicationBackend, CommunicationBackendReceiver},
};

/// Tracks whether peer endpoints are reachable, so a caller can avoid sending to an absent peer.
///
/// Obtain one from [`IpcClient::reachability`](crate::IpcClient::reachability) and call
/// [`track`](Self::track) with a peer's endpoint to get a [`ReachabilityHandle`]; query the handle
/// with [`ReachabilityHandle::is_reachable`]. A handle is a live subscription — hold it for as long
/// as you care about the endpoint and drop it to stop tracking.
///
/// The tracker is the factory and router: it hands out (deduped) handles, and feeds inbound control
/// frames to the right endpoint's handle state. The per-endpoint ping loop lives on the handle's
/// shared inner (see [`ReachabilityHandle`]).
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
    /// single inner (and its single ping loop); the loop is spawned only when the first handle for
    /// an endpoint is created.
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

        let inner = ReachabilityHandleInner::new(
            endpoint.clone(),
            self.send_fn.clone(),
            self.reach_fn.clone(),
            Arc::downgrade(&self.registry),
        );
        map.insert(endpoint, Arc::downgrade(&inner));
        inner.spawn_loop();

        ReachabilityHandle { inner }
    }

    /// Start consuming the inbound control stream: record liveness for every control frame and
    /// answer pings with a pong. Runs until `cancellation_token` is cancelled.
    ///
    /// Call this once when the client starts. It is required even when the tracker is not actively
    /// tracking anything, so a passive peer (e.g. the desktop leader) still answers pings.
    pub(crate) fn start<R: CommunicationBackendReceiver>(
        self: &Arc<Self>,
        control: ControlReceiver<R>,
        cancellation_token: CancellationToken,
    ) {
        let tracker = self.clone();
        let future = async move {
            loop {
                select! {
                    _ = cancellation_token.cancelled() => break,
                    received = control.receive() => match received {
                        Ok(incoming) => tracker.handle_inbound(incoming).await,
                        Err(error) if error.is_fatal() => break,
                        Err(_) => {}
                    },
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
    }

    /// Record liveness for the source (if it is tracked) and, for a ping, answer with a pong.
    async fn handle_inbound(&self, incoming: IncomingControlMessage) {
        let source = incoming.source.to_endpoint();

        if let Some(inner) = self
            .registry
            .lock()
            .expect("reachability registry poisoned")
            .get(&source)
            .and_then(Weak::upgrade)
        {
            inner.mark_alive();
        }

        if incoming.message == ControlMessage::Ping {
            (self.send_fn)(ControlMessage::Pong.to_outgoing(source)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        endpoint::{HostId, Source},
        message::OutgoingMessage,
        traits::Reachability,
    };

    const ENDPOINT: Endpoint = Endpoint::DesktopMain;

    /// Builds a tracker whose transport answers `reach` and records every outgoing frame.
    fn mock_tracker(
        reach: Reachability,
    ) -> (Arc<ReachabilityTracker>, Arc<Mutex<Vec<OutgoingMessage>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = sent.clone();
        let send_fn: SendFn = Arc::new(move |message| {
            let sent = sent_clone.clone();
            Box::pin(async move {
                sent.lock().unwrap().push(message);
            })
        });
        let reach_fn: ReachFn = Arc::new(move |_| Box::pin(async move { reach }));
        (Arc::new(ReachabilityTracker::new(send_fn, reach_fn)), sent)
    }

    fn incoming(source: Source, message: ControlMessage) -> IncomingControlMessage {
        IncomingControlMessage { message, source }
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
    async fn unsupported_falls_back_to_liveness() {
        let (tracker, _sent) = mock_tracker(Reachability::Unsupported);
        let handle = tracker.track(ENDPOINT);

        // No control frame seen yet -> not reachable.
        assert!(!handle.is_reachable().await);

        // An inbound control frame from the tracked endpoint marks it live.
        tracker
            .handle_inbound(incoming(Source::DesktopMain, ControlMessage::Pong))
            .await;
        assert!(handle.is_reachable().await);
    }

    #[tokio::test]
    async fn answers_inbound_ping_with_pong() {
        let (tracker, sent) = mock_tracker(Reachability::Unsupported);
        let web = Source::Web {
            tab_id: 7,
            document_id: "doc".to_owned(),
            origin: "https://example.com".to_owned(),
        };

        tracker
            .handle_inbound(incoming(web, ControlMessage::Ping))
            .await;

        let sent = sent.lock().unwrap();
        assert!(sent.iter().any(|m| {
            m.topic.as_deref() == Some(ControlMessage::Pong.topic())
                && m.destination
                    == (Endpoint::Web {
                        tab_id: 7,
                        document_id: "doc".to_owned(),
                    })
        }));
    }

    #[tokio::test]
    async fn track_dedupes_by_endpoint() {
        let (tracker, _sent) = mock_tracker(Reachability::Unsupported);
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
        let (tracker, _sent) = mock_tracker(Reachability::Unsupported);
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
        // Unsupported -> the loop emits at least one ping promptly.
        let (tracker, sent) = mock_tracker(Reachability::Unsupported);
        let _handle = tracker.track(ENDPOINT);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            sent.lock()
                .unwrap()
                .iter()
                .any(|m| m.topic.as_deref() == Some(ControlMessage::Ping.topic())),
            "an Unsupported transport should be probed with a ping"
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
        let (tracker, sent) = mock_tracker(Reachability::Unsupported);
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
