//! A reachability tracker to keep track of which endponits ar reachable.
//!
//! Followers continuously send a lightweight plaintext ping to their leader; the leader replies
//! with a pong. These messages travel over the raw transport and are deliberately NOT routed
//! through the SDK crypto channel — they exist only to measure liveness. The
//! [`ReachabilityTracker`] records the timestamp of the last message seen from each
//! peer and derives activity from it; an endpoint is considered reachable/active when that
//! timestamp is within [`ACTIVE_WINDOW`].

use std::{collections::HashMap, sync::Mutex, time::Duration};

use tokio::sync::Notify;
use web_time::Instant;

use crate::endpoint::Endpoint;

/// Topic marking a plaintext reachability ping.
pub(crate) const REACHABILITY_PING_TOPIC: &str = "$bitwarden_reachability_ping";
/// Topic marking a plaintext reachability pong (the reply to a ping).
pub(crate) const REACHABILITY_PONG_TOPIC: &str = "$bitwarden_reachability_pong";

/// Whether `topic` marks a plaintext reachability ping/pong that must bypass the crypto channel.
pub(crate) fn is_reachability_topic(topic: Option<&str>) -> bool {
    matches!(
        topic,
        Some(REACHABILITY_PING_TOPIC) | Some(REACHABILITY_PONG_TOPIC)
    )
}

/// An endpoint is "active"/reachable when the last message from it was within this window.
pub(crate) const ACTIVE_WINDOW: Duration = Duration::from_secs(5);
/// Ping cadence while the peer is active. Must be `< ACTIVE_WINDOW` to sustain activity.
pub(crate) const ACTIVE_PING_INTERVAL: Duration = Duration::from_secs(2);
/// Back-off ping cadence while the peer is inactive (e.g. not installed / not running).
pub(crate) const INACTIVE_PING_INTERVAL: Duration = Duration::from_secs(10);

/// Tracks the timestamp of the last message seen from each endpoint and derives activity
/// status from it.
pub struct ReachabilityTracker {
    last_message: Mutex<HashMap<Endpoint, Instant>>,
    active_state: Mutex<HashMap<Endpoint, bool>>,
    /// Concrete leader endpoints this client actively pings.
    ping_targets: Vec<Endpoint>,
    /// Woken on a stale->active transition so the ping scheduler retightens its cadence.
    rearm: Notify,
    /// Injectable clock, so tests can advance time deterministically.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl ReachabilityTracker {
    /// Create a tracker that pings the given leader endpoints.
    pub(crate) fn new(ping_targets: Vec<Endpoint>) -> Self {
        Self::with_clock(ping_targets, Box::new(Instant::now))
    }

    /// Create a tracker with an injectable clock (used by tests).
    pub(crate) fn with_clock(
        ping_targets: Vec<Endpoint>,
        now: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self {
            last_message: Mutex::new(HashMap::new()),
            active_state: Mutex::new(HashMap::new()),
            ping_targets,
            rearm: Notify::new(),
            now,
        }
    }

    /// Record that a message was just received from `endpoint`.
    pub(crate) fn record(&self, endpoint: &Endpoint) {
        self.last_message
            .lock()
            .expect("reachability last_message mutex poisoned")
            .insert(endpoint.clone(), (self.now)());
        self.emit_if_changed(endpoint, true);
    }

    /// Immediately mark `endpoint` as stale, as if no message was ever received from it.
    pub(crate) fn invalidate(&self, endpoint: &Endpoint) {
        self.last_message
            .lock()
            .expect("reachability last_message mutex poisoned")
            .remove(endpoint);
        self.emit_if_changed(endpoint, false);
    }

    /// Returns whether a destination is reachable
    pub fn is_reachable(&self, endpoint: &Endpoint) -> bool {
        let last = self
            .last_message
            .lock()
            .expect("reachability last_message mutex poisoned")
            .get(endpoint)
            .copied();
        match last {
            Some(last) => (self.now)().saturating_duration_since(last) < ACTIVE_WINDOW,
            None => false,
        }
    }

    /// Adaptive ping cadence for `endpoint`: faster while active, backed off while inactive.
    /// Polling this is also where staleness transitions surface (the ping scheduler calls it
    /// every cycle).
    pub(crate) fn interval_for(&self, endpoint: &Endpoint) -> Duration {
        let active = self.is_reachable(endpoint);
        self.emit_if_changed(endpoint, active);
        if active {
            ACTIVE_PING_INTERVAL
        } else {
            INACTIVE_PING_INTERVAL
        }
    }

    /// The leader endpoints this client should actively ping.
    pub(crate) fn ping_targets(&self) -> &[Endpoint] {
        &self.ping_targets
    }

    /// Resolves the next time a stale->active transition retightens the ping cadence.
    pub(crate) async fn rearmed(&self) {
        self.rearm.notified().await;
    }

    fn emit_if_changed(&self, endpoint: &Endpoint, active: bool) {
        let changed = {
            let mut states = self
                .active_state
                .lock()
                .expect("reachability active_state mutex poisoned");
            let previous = states.get(endpoint).copied().unwrap_or(false);
            if previous != active {
                states.insert(endpoint.clone(), active);
                true
            } else {
                false
            }
        };

        if changed {
            if active {
                tracing::debug!(?endpoint, "IPC endpoint became reachable");
                // Wake the ping scheduler so it reschedules at the (now active) cadence.
                self.rearm.notify_one();
            } else {
                tracing::warn!(?endpoint, "IPC endpoint became unreachable");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::endpoint::HostId;

    /// A controllable clock: `now()` returns a base instant plus the accumulated advance.
    #[derive(Clone)]
    struct MockClock {
        base: Instant,
        advance_ms: Arc<AtomicU64>,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                advance_ms: Arc::new(AtomicU64::new(0)),
            }
        }

        fn advance(&self, by: Duration) {
            self.advance_ms
                .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }

        fn clock(&self) -> Box<dyn Fn() -> Instant + Send + Sync> {
            let base = self.base;
            let advance_ms = self.advance_ms.clone();
            Box::new(move || base + Duration::from_millis(advance_ms.load(Ordering::SeqCst)))
        }
    }

    fn tracker(targets: Vec<Endpoint>) -> (ReachabilityTracker, MockClock) {
        let clock = MockClock::new();
        let tracker = ReachabilityTracker::with_clock(targets, clock.clock());
        (tracker, clock)
    }

    const EXTENSION: Endpoint = Endpoint::BrowserBackground { id: HostId::Own };

    #[test]
    fn inactive_until_first_message() {
        let (tracker, _clock) = tracker(vec![EXTENSION]);
        assert!(!tracker.is_reachable(&EXTENSION));
    }

    #[test]
    fn active_immediately_after_record() {
        let (tracker, _clock) = tracker(vec![EXTENSION]);
        tracker.record(&EXTENSION);
        assert!(tracker.is_reachable(&EXTENSION));
    }

    #[test]
    fn stays_active_within_window_then_goes_stale() {
        let (tracker, clock) = tracker(vec![EXTENSION]);
        tracker.record(&EXTENSION);
        clock.advance(ACTIVE_WINDOW - Duration::from_millis(1));
        assert!(tracker.is_reachable(&EXTENSION));
        clock.advance(Duration::from_millis(1));
        assert!(!tracker.is_reachable(&EXTENSION));
    }

    #[test]
    fn adaptive_cadence_follows_activity() {
        let (tracker, clock) = tracker(vec![EXTENSION]);
        assert_eq!(tracker.interval_for(&EXTENSION), INACTIVE_PING_INTERVAL);
        tracker.record(&EXTENSION);
        assert_eq!(tracker.interval_for(&EXTENSION), ACTIVE_PING_INTERVAL);
        clock.advance(ACTIVE_WINDOW);
        assert_eq!(tracker.interval_for(&EXTENSION), INACTIVE_PING_INTERVAL);
    }

    #[test]
    fn endpoints_tracked_independently() {
        let (tracker, _clock) = tracker(vec![Endpoint::DesktopRenderer]);
        tracker.record(&Endpoint::DesktopMain);
        // Each endpoint is keyed individually; recording the main process does not make the
        // renderer reachable.
        assert!(tracker.is_reachable(&Endpoint::DesktopMain));
        assert!(!tracker.is_reachable(&Endpoint::DesktopRenderer));
    }

    #[test]
    fn web_tabs_tracked_independently() {
        let tab1 = Endpoint::Web {
            tab_id: 1,
            document_id: "a".to_owned(),
        };
        let tab2 = Endpoint::Web {
            tab_id: 2,
            document_id: "b".to_owned(),
        };
        let (tracker, _clock) = tracker(vec![]);
        tracker.record(&tab1);
        assert!(tracker.is_reachable(&tab1));
        assert!(!tracker.is_reachable(&tab2));
    }

    #[test]
    fn invalidate_marks_stale_immediately() {
        let (tracker, _clock) = tracker(vec![EXTENSION]);
        tracker.record(&EXTENSION);
        assert!(tracker.is_reachable(&EXTENSION));
        tracker.invalidate(&EXTENSION);
        assert!(!tracker.is_reachable(&EXTENSION));
    }

    #[tokio::test]
    async fn record_rearms_scheduler_on_activation() {
        let (tracker, _clock) = tracker(vec![EXTENSION]);
        // A stale->active transition must wake a waiter.
        tracker.record(&EXTENSION);
        // notify_one stored a permit, so rearmed() resolves immediately.
        tracker.rearmed().await;
    }
}
