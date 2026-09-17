#![doc = include_str!("../README.md")]

#[cfg(target_arch = "wasm32")]
mod browser;
mod descriptor;
mod event;
mod timeline;
/// Re-exported by `bitwarden-wasm-internal` so wasm_bindgen picks the bindings up.
#[cfg(feature = "wasm")]
pub mod wasm;

pub use descriptor::PerformanceEventDescriptor;
pub use event::PerformanceEvent;

/// Nominal duration given to [`log_event`] entries. A zero-length entry cannot be clicked in the
/// DevTools performance panel, so point-in-time events are widened to stay selectable.
pub const INSTANT_EVENT_DURATION_MS: f64 = 50.0;

/// Property flagging an entry whose duration is nominal rather than measured.
pub const INSTANT_EVENT_PROPERTY: &str = "instant";

/// Records a standalone named point on the timeline, for a step that belongs to no one event.
///
/// Prefer [`PerformanceEvent::mark`], which scopes the mark to the event it belongs to.
pub fn mark(name: &str) {
    timeline::mark(name);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> PerformanceEventDescriptor {
        PerformanceEventDescriptor::new("Group", "Track", "Name")
    }

    /// Off wasm the backend does nothing, so these only pin that the event builds, accepts
    /// after-the-fact properties and is written exactly once.
    #[test]
    fn event_writes_on_drop() {
        let mut event = descriptor().prop("method", "pin").start();
        event.mark("halfway");
        event.prop("outcome", "ok");
    }

    #[test]
    fn event_writes_on_early_return() {
        fn traced() -> Option<()> {
            let _event = descriptor().start();
            None?
        }

        assert!(traced().is_none());
    }

    #[test]
    fn finish_writes_before_the_scope_ends() {
        let event = descriptor().start();
        event.finish();
    }

    #[test]
    fn record_result_only_reports_failures() {
        let mut event = descriptor().start();

        event.record_result(&Ok::<(), &str>(()));
        assert!(properties(&event).is_empty());

        event.record_result(&Err::<(), &str>("boom"));
        assert_eq!(
            properties(&event),
            vec![("error".to_owned(), "\"boom\"".to_owned())]
        );
    }

    #[test]
    fn log_event_flags_the_nominal_duration() {
        let flagged = descriptor().prop(INSTANT_EVENT_PROPERTY, true);

        assert_eq!(
            flagged.properties,
            vec![(INSTANT_EVENT_PROPERTY.to_owned(), "true".to_owned())]
        );

        descriptor().log();
    }

    fn properties(event: &PerformanceEvent) -> Vec<(String, String)> {
        event.descriptor_for_test().properties.clone()
    }
}
