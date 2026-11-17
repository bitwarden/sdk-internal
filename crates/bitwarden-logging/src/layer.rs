//! Tracing subscriber layer for Flight Recorder.

use std::sync::Arc;

use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context};

use crate::{
    CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, LocalBufferSink, sink::SinkSlot,
    suppress::is_suppressed,
};

/// A tracing subscriber layer that captures log events into the active sink.
///
/// The sink starts as a [`LocalBufferSink`] over the layer's buffer. Events from the
/// `bitwarden_logging` target, and events emitted inside
/// [`without_flight_recorder`](crate::without_flight_recorder), are filtered out to prevent
/// infinite recursion.
pub struct FlightRecorderLayer {
    buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
    sink: SinkSlot,
    level: tracing::Level,
}

impl std::fmt::Debug for FlightRecorderLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlightRecorderLayer")
            .field("level", &self.level)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl FlightRecorderLayer {
    /// Create a new FlightRecorderLayer with the given configuration.
    #[must_use]
    pub fn new(config: FlightRecorderConfig) -> Self {
        let buffer = Arc::new(CircularBuffer::new(config.buffer_size));
        let sink = SinkSlot::new(Arc::new(LocalBufferSink::new(Arc::clone(&buffer))));
        Self {
            buffer,
            sink,
            level: config.level,
        }
    }

    /// Get a reference to the underlying buffer.
    ///
    /// This can be used to access the buffer for reading captured events.
    pub fn buffer(&self) -> Arc<CircularBuffer<FlightRecorderEvent>> {
        Arc::clone(&self.buffer)
    }

    pub(crate) fn sink(&self) -> SinkSlot {
        self.sink.clone()
    }
}

impl<S> Layer<S> for FlightRecorderLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        // Filter out our own logging to prevent recursion
        if metadata.target().starts_with("bitwarden_logging") {
            return;
        }

        // Skip events more verbose than configured level
        if *metadata.level() > self.level {
            return;
        }

        if is_suppressed() {
            return;
        }

        self.sink.push(event.into());
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn test_layer_creation() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_layer_captures_events() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "test::module", "hello from test");
        });

        let events = buffer.read();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "hello from test");
        assert_eq!(events[0].level, "INFO");
    }

    #[test]
    fn test_layer_filters_own_crate() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "bitwarden_logging::internal", "should be skipped");
            tracing::info!(target: "bitwarden_logging", "should be skipped");
            tracing::info!("should be skipped");
        });

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_layer_filters_by_level() {
        let config = FlightRecorderConfig::new(
            NonZeroUsize::new(100).expect("non-zero"),
            tracing::Level::INFO,
        );
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "test::module", "should be skipped");
            tracing::info!(target: "test::module", "should be captured");
            tracing::warn!(target: "test::module", "should also be captured");
        });

        let events = buffer.read();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].level, "INFO");
        assert_eq!(events[1].level, "WARN");
    }

    #[tokio::test]
    async fn test_layer_skips_suppressed_events() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        crate::without_flight_recorder(async {
            tracing::info!(target: "any_crate", "should be skipped");
        })
        .await;
        tracing::info!(target: "any_crate", "should be captured");

        let events = buffer.read();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "should be captured");
    }

    #[test]
    fn test_buffer_shared_via_arc() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer1 = layer.buffer();
        let buffer2 = layer.buffer();

        assert!(Arc::ptr_eq(&buffer1, &buffer2));

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "test::module", "shared buffer test");
        });

        // Both handles see the same events
        assert_eq!(buffer1.read().len(), 1);
        assert_eq!(buffer2.read().len(), 1);
    }

    #[test]
    fn test_layer_captures_structured_fields() {
        let config = FlightRecorderConfig::default();
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "test::module", user_id = "abc-123", "login attempt");
        });

        let events = buffer.read();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "login attempt");
        assert_eq!(events[0].target, "test::module");
        assert_eq!(
            events[0].fields.get("user_id"),
            Some(&"abc-123".to_string())
        );
    }
}
