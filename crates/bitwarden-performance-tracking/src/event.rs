//! A timed event, spanning the operation it was started around.

use crate::{
    descriptor::PerformanceEventDescriptor,
    timeline::{self, Instant},
};

/// Draws its entry when dropped, spanning from the moment [`start_event`] was called.
///
/// [`start_event`]: crate::start_event
pub struct PerformanceEvent {
    // Taken on drop, and `Some` for the whole life of the event. The `Option` exists only because
    // writing the measurement consumes the descriptor and `Drop::drop` cannot move out of `self`.
    descriptor: Option<PerformanceEventDescriptor>,
    started_at: Instant,
}

impl PerformanceEvent {
    pub(crate) fn start(descriptor: PerformanceEventDescriptor) -> Self {
        Self {
            descriptor: Some(descriptor),
            started_at: timeline::now(),
        }
    }

    /// Records an intermediate mark on the event's timeline, scoped to this event — the point a
    /// PIN was validated, the point a network round trip returned.
    pub fn mark(&self, name: &str) {
        let Some(descriptor) = self.descriptor.as_ref() else {
            return;
        };

        timeline::mark(&format!(
            "[{}] {}: {name}",
            descriptor.category, descriptor.name
        ));
    }

    /// Adds a key/value row to the entry, for a detail known only once the operation has run — an
    /// outcome, an error kind.
    ///
    /// The value is rendered verbatim, so it must never carry key material or vault data.
    pub fn prop(&mut self, key: &str, value: impl std::fmt::Display) {
        let Some(descriptor) = self.descriptor.take() else {
            return;
        };

        self.descriptor = Some(descriptor.prop(key, value));
    }

    /// Attaches the error to the entry when `result` failed, and does nothing when it succeeded.
    ///
    /// The `Debug` output of an error is assumed not to carry key material or vault data, which
    /// holds for every error type in the SDK.
    pub fn record_result<T, E: std::fmt::Debug>(&mut self, result: &Result<T, E>) {
        let Err(error) = result else {
            return;
        };

        self.prop("error", format!("{error:?}"));
    }

    /// Writes the measurement spanning from the event's start until now.
    ///
    /// Only needed to end the entry before the enclosing scope does; dropping the event writes the
    /// same measurement.
    pub fn finish(self) {
        drop(self);
    }

    #[cfg(test)]
    pub(crate) fn descriptor_for_test(&self) -> &PerformanceEventDescriptor {
        self.descriptor
            .as_ref()
            .expect("the descriptor is only taken when the event is written")
    }
}

impl Drop for PerformanceEvent {
    fn drop(&mut self) {
        let Some(descriptor) = self.descriptor.take() else {
            return;
        };

        timeline::measure(descriptor, self.started_at, timeline::now());
    }
}
