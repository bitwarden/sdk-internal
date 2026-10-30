//! Destinations for captured Flight Recorder events.

use std::sync::{Arc, RwLock};

use crate::{CircularBuffer, FlightRecorderEvent};

/// Destination for events captured by the Flight Recorder.
///
/// Both the tracing layer and externally written events (e.g. from TypeScript) push through the
/// active sink, so a sink sees every captured event regardless of where it came from.
pub trait FlightRecorderSink: Send + Sync {
    /// Accept one captured event.
    fn push(&self, event: FlightRecorderEvent);
}

/// Sink that stores events in an in-memory [`CircularBuffer`].
pub struct LocalBufferSink {
    buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
}

impl LocalBufferSink {
    /// Create a sink that pushes into `buffer`.
    pub fn new(buffer: Arc<CircularBuffer<FlightRecorderEvent>>) -> Self {
        Self { buffer }
    }
}

impl FlightRecorderSink for LocalBufferSink {
    fn push(&self, event: FlightRecorderEvent) {
        self.buffer.push(event);
    }
}

/// Swappable slot holding the active sink, shared by the layer and the global write path.
#[derive(Clone)]
pub(crate) struct SinkSlot(Arc<RwLock<Arc<dyn FlightRecorderSink>>>);

impl SinkSlot {
    pub(crate) fn new(sink: Arc<dyn FlightRecorderSink>) -> Self {
        Self(Arc::new(RwLock::new(sink)))
    }

    pub(crate) fn push(&self, event: FlightRecorderEvent) {
        self.0
            .read()
            .expect("FlightRecorder sink lock poisoned")
            .push(event);
    }

    pub(crate) fn set(&self, sink: Arc<dyn FlightRecorderSink>) {
        *self.0.write().expect("FlightRecorder sink lock poisoned") = sink;
    }
}

impl std::fmt::Debug for SinkSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkSlot").finish_non_exhaustive()
    }
}
