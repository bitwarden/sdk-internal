//! The JavaScript-facing façade, so the web and desktop clients draw their entries through the
//! same implementation the SDK uses rather than a second copy of it.
//!
//! Mirrors `@bitwarden/performance-tracking`: a descriptor of namespace / category / name, a timed
//! event, and a point-in-time event.
//!
//! ```ts
//! const event = startPerformanceEvent("Unlock", "DefaultUnlockService", "unlockWithPin", [
//!   ["userId", userId],
//! ]);
//! event.mark("pin validated");
//! event.finish([["outcome", "success"]]);
//! ```

use js_sys::Array;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{PerformanceEventDescriptor, event::PerformanceEvent};

/// A timed event, drawn on the timeline when [`JsPerformanceEvent::finish`] is called.
///
/// Unlike the Rust API there is no drop guard to fall back on — JavaScript has no scope-bound
/// destruction — so an event that is never finished is never drawn, and one that is neither
/// finished nor `free()`d leaks. Callers should finish every event they start.
#[wasm_bindgen(js_name = PerformanceEvent)]
pub struct JsPerformanceEvent {
    inner: PerformanceEvent,
}

#[wasm_bindgen(js_class = PerformanceEvent)]
impl JsPerformanceEvent {
    /// Records an intermediate mark on the event's timeline, scoped to this event.
    pub fn mark(&self, name: &str) {
        self.inner.mark(name);
    }

    /// Writes the measurement spanning from the event's start until now.
    ///
    /// `properties` are merged with the ones given at start; see [`start_performance_event`] for
    /// the expected shape.
    /// Consumes the event, so the JavaScript handle is freed rather than leaked; calling it twice
    /// is a programming error the bindings report as a null pointer.
    pub fn finish(self, properties: Option<Array>) {
        let mut event = self.inner;

        for (key, value) in pairs(properties) {
            event.prop(&key, value);
        }
    }
}

/// Starts a timed event on the `category` track of the `namespace` track group.
///
/// `properties` is an array of `[key, value]` pairs, as in the TypeScript API; values are rendered
/// verbatim in DevTools, so they must never carry key material or vault data.
#[wasm_bindgen(js_name = startPerformanceEvent)]
pub fn start_performance_event(
    namespace: String,
    category: String,
    name: String,
    properties: Option<Array>,
) -> JsPerformanceEvent {
    JsPerformanceEvent {
        inner: descriptor(namespace, category, name, properties).start(),
    }
}

/// Records a point-in-time event, written with a nominal duration so it stays selectable.
#[wasm_bindgen(js_name = logPerformanceEvent)]
pub fn log_performance_event(
    namespace: String,
    category: String,
    name: String,
    properties: Option<Array>,
) {
    descriptor(namespace, category, name, properties).log();
}

/// Records a standalone named point on the timeline.
#[wasm_bindgen(js_name = logPerformanceMark)]
pub fn log_performance_mark(name: &str) {
    crate::mark(name);
}

fn descriptor(
    namespace: String,
    category: String,
    name: String,
    properties: Option<Array>,
) -> PerformanceEventDescriptor {
    let mut descriptor = PerformanceEventDescriptor::new(namespace, category, name);

    for (key, value) in pairs(properties) {
        descriptor = descriptor.prop(&key, value);
    }

    descriptor
}

/// Reads `[key, value]` pairs, skipping anything that is not one — a malformed property must not
/// cost the caller its entry.
fn pairs(properties: Option<Array>) -> Vec<(String, String)> {
    let Some(properties) = properties else {
        return Vec::new();
    };

    properties
        .iter()
        .filter_map(|pair| {
            let pair = Array::from(&pair);
            if pair.length() < 2 {
                return None;
            }

            let value = pair.get(1);

            // Non-strings are stringified the way JavaScript would — `Debug` for `JsValue` is
            // implemented by calling back into JS — so `[["bytes", 512]]` reads as `512`.
            Some((
                pair.get(0).as_string()?,
                value.as_string().unwrap_or_else(|| format!("{value:?}")),
            ))
        })
        .collect()
}
