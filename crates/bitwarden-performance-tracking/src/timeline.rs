//! The target-independent half of the backend: reading the timeline clock, and handing a finished
//! entry to the platform. On every target but `wasm32` nothing is written.

use crate::descriptor::PerformanceEventDescriptor;

/// A point on the DevTools timeline clock, in fractional milliseconds.
///
/// Not a wall clock, and always zero off `wasm32`.
// Read only by the wasm backend; see the note on `PerformanceEventDescriptor`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant(pub(crate) f64);

/// Reads the current point on the DevTools timeline clock (`performance.now()`).
pub(crate) fn now() -> Instant {
    #[cfg(target_arch = "wasm32")]
    return Instant(crate::browser::performance_now());

    #[cfg(not(target_arch = "wasm32"))]
    Instant(0.0)
}

/// Draws `descriptor` as an entry spanning `start` to `end`, and debug-logs the same data so a
/// consumer without DevTools open still sees it in the flight recorder.
pub(crate) fn measure(descriptor: PerformanceEventDescriptor, start: Instant, end: Instant) {
    let entry_name = descriptor.entry_name();

    #[cfg(target_arch = "wasm32")]
    crate::browser::measure(&entry_name, &descriptor, start, end);

    tracing::debug!(
        properties = ?descriptor.properties,
        "{entry_name} took {}ms",
        end.0 - start.0
    );

    #[cfg(not(target_arch = "wasm32"))]
    let _ = (descriptor, start, end);
}

/// Draws a named point on the timeline, without a duration.
pub(crate) fn mark(name: &str) {
    #[cfg(target_arch = "wasm32")]
    crate::browser::mark(name);

    tracing::debug!("{name}");
}
