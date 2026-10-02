//! Captured `tracing` output, which is what the harness observes instead of keeping its own event
//! log.
//!
//! A `tracing` subscriber is process-wide, and the test binary runs its tests concurrently, so
//! every event the harness emits carries the id of the topology that produced it and assertions
//! filter on that. Events from the crate under test have no topology id; they are still captured,
//! and still printed in the failure dump, because they are most of what makes a failure readable.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{filter::LevelFilter, layer::Context, prelude::*, registry::LookupSpan};
use web_time::Instant;

/// One captured event: its message plus every field, flattened to strings.
#[derive(Clone, Debug)]
pub(crate) struct CapturedEvent {
    /// Milliseconds since the capture buffer was installed.
    pub(crate) at: u128,
    pub(crate) target: String,
    pub(crate) message: String,
    pub(crate) fields: HashMap<String, String>,
}

impl CapturedEvent {
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub(crate) fn kind(&self) -> Option<&str> {
        self.field(KIND_FIELD)
    }

    pub(crate) fn device(&self) -> &str {
        self.field(DEVICE_FIELD).unwrap_or("-")
    }

    /// The user this event concerned, if it named one.
    pub(crate) fn user_id(&self) -> Option<&str> {
        self.field("user_id").filter(|user| !user.is_empty())
    }
}

/// Field name the harness stamps onto every event so concurrent tests do not read each other's.
pub(crate) const TOPOLOGY_FIELD: &str = "topology";
/// Field name identifying which simulated device an event came from.
pub(crate) const DEVICE_FIELD: &str = "device";
/// Field name carrying what kind of thing happened. A field rather than the message, because
/// `tracing` needs a literal message and the harness picks its kinds at runtime.
pub(crate) const KIND_FIELD: &str = "kind";

/// Marks a device event the test itself issued, as opposed to a protocol-driven one.
pub(crate) const TEST_MANUAL_LOCK: &str = "ManualLock (test)";
pub(crate) const TEST_MANUAL_UNLOCK: &str = "ManualUnlock (test)";
pub(crate) const REPLAYED_MANUAL_LOCK: &str = "ManualLock (replayed from protocol lock)";

/// What the harness reports. These are the events assertions filter on.
pub(crate) mod kind {
    pub(crate) const LOCK_START: &str = "lock_start";
    pub(crate) const LOCK_END: &str = "lock_end";
    pub(crate) const UNLOCK_START: &str = "unlock_start";
    pub(crate) const UNLOCK_END: &str = "unlock_end";
    pub(crate) const DEVICE_EVENT: &str = "device_event";
    pub(crate) const SUPPRESS_TIMEOUT: &str = "suppress_timeout";
    pub(crate) const IPC_SEND: &str = "ipc_send";
    pub(crate) const IPC_UNREACHABLE: &str = "ipc_unreachable";
    pub(crate) const RELOAD: &str = "reload";
    pub(crate) const OFFLINE: &str = "offline";
    pub(crate) const ONLINE: &str = "online";
    pub(crate) const OVERLAP: &str = "overlap";
    pub(crate) const NOTE: &str = "note";
}

/// Reports something a simulated device did, attributed to its topology so concurrent tests stay
/// separable.
pub(crate) fn emit_log(
    topology: TopologyId,
    device: &str,
    kind: &'static str,
    user_id: Option<bitwarden_core::UserId>,
    detail: &str,
) {
    let user = user_id.map(|user| user.to_string()).unwrap_or_default();
    tracing::debug!(
        target: "shared_unlock_harness",
        topology = topology.as_value(),
        device,
        kind,
        user_id = %user,
        detail,
        "harness"
    );
}

/// Identifies one topology's events within the process-wide capture buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TopologyId(u64);

impl TopologyId {
    pub(crate) fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) fn as_value(&self) -> u64 {
        self.0
    }
}

/// The capture buffer, bucketed by topology.
///
/// One flat buffer would make every 5ms poll in [`super::assertions`] walk every concurrently
/// running test's events while holding the lock that each device's `emit` needs to make progress.
#[derive(Default)]
struct Captured {
    by_topology: HashMap<u64, Vec<CapturedEvent>>,
    /// Events from the crate under test, which carry no topology field. Read only when formatting
    /// a failure, so these stay in one bucket.
    unattributed: Vec<CapturedEvent>,
}

struct CaptureState {
    started_at: Instant,
    captured: Mutex<Captured>,
}

fn state() -> &'static Arc<CaptureState> {
    static STATE: OnceLock<Arc<CaptureState>> = OnceLock::new();
    STATE.get_or_init(|| {
        let state = Arc::new(CaptureState {
            started_at: Instant::now(),
            captured: Mutex::new(Captured::default()),
        });

        // Installed once for the whole test binary.
        //
        // Two layers. The capture layer always runs at `debug`, because that is the level the
        // protocol's tracing uses and the assertions read those events. The printing layer is off
        // unless `RUST_LOG` asks for it, so an ordinary run stays quiet:
        //
        //     RUST_LOG=debug cargo test -p bitwarden-shared-unlock -- --nocapture
        //
        // Add a test-name filter when doing that. The tests run concurrently, so with more than one
        // in flight the printed lines interleave and only the `topology` field tells them apart.
        let printing = tracing_subscriber::fmt::layer()
            // Routes through libtest's capture, so the output obeys `--nocapture` and is attributed
            // to the test that produced it.
            .with_test_writer()
            .with_target(true)
            .with_filter(tracing_subscriber::EnvFilter::from_default_env());

        let _ = tracing_subscriber::registry()
            .with(CaptureLayer(state.clone()).with_filter(LevelFilter::DEBUG))
            .with(printing)
            .try_init();

        state
    })
}

/// Installs the capture subscriber if it is not already installed. Every topology calls this.
pub(crate) fn install() {
    let _ = state();
}

/// Milliseconds since the capture buffer was installed, so assertions can bound a window.
pub(crate) fn now_ms() -> u128 {
    state().started_at.elapsed().as_millis()
}

/// Every event a topology emitted, oldest first.
pub(crate) fn events_for(topology: TopologyId) -> Vec<CapturedEvent> {
    state()
        .captured
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .by_topology
        .get(&topology.0)
        .cloned()
        .unwrap_or_default()
}

/// Everything captured while a topology was alive, including the crate's own tracing, formatted for
/// a failure message. This is the primary debugging output.
///
/// The crate's own events cannot be attributed to a topology, so a run with several tests in flight
/// shows every overlapping test's protocol tracing here, not just this one's.
pub(crate) fn format_since(topology: TopologyId, since_ms: u128) -> String {
    let mut events: Vec<CapturedEvent> = {
        let captured = state()
            .captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        captured
            .by_topology
            .get(&topology.0)
            .into_iter()
            .flatten()
            .chain(captured.unattributed.iter())
            .filter(|event| event.at >= since_ms)
            .cloned()
            .collect()
    };
    events.sort_by_key(|event| event.at);

    let mut out = String::from("\n--- captured log ---\n");
    for event in &events {
        let device = event.field(DEVICE_FIELD).unwrap_or("-");
        let mut fields: Vec<_> = event
            .fields
            .iter()
            .filter(|(name, value)| {
                name.as_str() != "message"
                    && name.as_str() != TOPOLOGY_FIELD
                    && name.as_str() != DEVICE_FIELD
                    && name.as_str() != KIND_FIELD
                    && !value.is_empty()
            })
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        fields.sort();

        // Harness events carry a `kind`; events from the crate under test carry a message, and are
        // worth marking as such so the two are distinguishable in the dump.
        let what = match event.kind() {
            Some(kind) => kind.to_owned(),
            None => format!("{} [{}]", event.message, event.target),
        };
        out.push_str(&format!(
            "{:>6}ms  {:<10}  {:<44}  {}\n",
            event.at,
            device,
            what,
            fields.join(" ")
        ));
    }
    out.push_str("--- end captured log ---\n");
    out
}

struct CaptureLayer(Arc<CaptureState>);

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let message = visitor.fields.remove("message").unwrap_or_default();
        let topology = visitor
            .fields
            .get(TOPOLOGY_FIELD)
            .and_then(|id| id.parse::<u64>().ok());
        let captured = CapturedEvent {
            at: self.0.started_at.elapsed().as_millis(),
            target: event.metadata().target().to_owned(),
            message,
            fields: visitor.fields,
        };

        let mut buffer = self
            .0
            .captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match topology {
            Some(topology) => buffer
                .by_topology
                .entry(topology)
                .or_default()
                .push(captured),
            None => buffer.unattributed.push(captured),
        }
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: HashMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }
}
