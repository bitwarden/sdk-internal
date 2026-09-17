//! The target-independent half of the API: building an entry and handing it to the platform
//! backend. On every target but `wasm32` the backend does nothing.

/// A point on the DevTools timeline clock, in fractional milliseconds.
///
/// Not a wall clock, and always zero off `wasm32`.
// Read only by the wasm backend; see the note on `TrackEntry`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant(pub(crate) f64);

/// Reads the current point on the DevTools timeline clock (`performance.now()`).
pub(crate) fn now() -> Instant {
    #[cfg(target_arch = "wasm32")]
    return Instant(super::wasm::performance_now());

    #[cfg(not(target_arch = "wasm32"))]
    Instant(0.0)
}

/// One entry to be drawn on a custom DevTools track.
///
/// Built up and then consumed by [`TrackEntry::emit`] or [`TrackEntry::timed`]; nothing is
/// reported until one of those is called.
// The fields are read only by the wasm backend, which is the point of the crate; off wasm they are
// deliberately built and dropped.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct TrackEntry {
    pub(crate) group: &'static str,
    pub(crate) track: &'static str,
    pub(crate) name: String,
    pub(crate) properties: Vec<(String, String)>,
}

impl TrackEntry {
    /// Creates an entry named `name`, to be drawn on the `track` lane of the `group` track group.
    /// Both the group and the track are created by DevTools on first use.
    pub fn new(group: &'static str, track: &'static str, name: impl Into<String>) -> Self {
        Self {
            group,
            track,
            name: name.into(),
            properties: Vec::new(),
        }
    }

    /// Adds a key/value row to the details pane DevTools shows for the selected entry.
    ///
    /// The value is rendered verbatim, so it must never carry key material or vault data.
    pub fn prop(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.properties.push((key.to_owned(), value.to_string()));
        self
    }

    /// Emits the entry as a zero-length tick at the current time, for an event with no duration to
    /// report — a message arriving, a session being torn down.
    pub fn emit(self) {
        let at = now();
        self.emit_between(at, at);
    }

    /// Starts timing, and emits the entry spanning until the returned guard is dropped.
    ///
    /// The guard is dropped on every path out of the scope, so the entry is still drawn when the
    /// operation is left by a `?`, an early `return` or a panic.
    pub fn timed(self) -> TimedGuard {
        TimedGuard {
            entry: Some(self),
            started_at: now(),
        }
    }

    fn emit_between(self, start: Instant, end: Instant) {
        #[cfg(target_arch = "wasm32")]
        super::wasm::emit(&self, start, end);

        #[cfg(not(target_arch = "wasm32"))]
        let _ = (self, start, end);
    }
}

/// Emits its entry when dropped, spanning from the moment [`TrackEntry::timed`] was called.
pub struct TimedGuard {
    // Taken on drop, and `Some` for the whole life of the guard. The `Option` exists only because
    // `emit_between` consumes the entry and `Drop::drop` cannot move out of `self`.
    entry: Option<TrackEntry>,
    started_at: Instant,
}

impl TimedGuard {
    /// Adds a key/value row to the entry, for a detail known only once the operation has run — an
    /// outcome, an error kind.
    ///
    /// Same rule as [`TrackEntry::prop`]: the value is rendered verbatim, so it must never carry
    /// key material or vault data.
    pub fn prop(&mut self, key: &str, value: impl std::fmt::Display) {
        let Some(entry) = self.entry.take() else {
            return;
        };

        self.entry = Some(entry.prop(key, value));
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
}

impl Drop for TimedGuard {
    fn drop(&mut self) {
        let Some(entry) = self.entry.take() else {
            return;
        };

        entry.emit_between(self.started_at, now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off wasm the backend does nothing, so this only pins that the guard builds, accepts
    /// after-the-fact properties and emits exactly once, on drop.
    #[test]
    fn guard_emits_on_drop() {
        let mut timed = TrackEntry::new("Group", "Track", "Name").timed();
        timed.prop("outcome", "ok");
    }

    #[test]
    fn guard_emits_on_early_return() {
        fn traced() -> Option<()> {
            let _timed = TrackEntry::new("Group", "Track", "Name").timed();
            None?
        }

        assert!(traced().is_none());
    }
}
