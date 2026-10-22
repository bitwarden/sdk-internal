//! Records IPC activity on the browser performance timeline, so it shows up as custom tracks in
//! the Chrome DevTools Performance panel. A no-op outside of WASM.
//!
//! ```text
//! IPC
//! ├─ Sent        [msg]   [msg]          one entry per message, at least 1 ms wide
//! ├─ Received       [msg]     [msg]
//! ├─ Requests    [── MyRequest ──]      request sent until response received
//! ├─ Handlers         [MyRequest]       remote handler run
//! └─ Handshakes  [Noise handshake]
//! ```

/// DevTools track an entry is drawn on, all grouped under "IPC".
#[derive(Clone, Copy)]
pub(crate) enum Track {
    Sent,
    Received,
    Requests,
    Handlers,
    Handshakes,
}

/// How long an entry is drawn for.
#[derive(Clone, Copy)]
pub(crate) enum Duration {
    /// From span creation until drop.
    Actual,
    /// From span creation until drop, but at least [`MIN_MESSAGE_DURATION_MS`] so near-instant
    /// messages stay visible.
    AtLeastMessage,
}

/// Name and key/value rows shown in the DevTools entry summary, e.g. `RpcRequestMessage` with
/// `[("Destination", "DesktopMain")]`.
#[cfg_attr(not(all(feature = "wasm", target_arch = "wasm32")), allow(dead_code))]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) properties: Vec<(&'static str, String)>,
}

/// Minimum drawn duration of a single sent or received message.
#[cfg_attr(not(all(feature = "wasm", target_arch = "wasm32")), allow(dead_code))]
const MIN_MESSAGE_DURATION_MS: f64 = 1.0;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub(crate) use wasm::span;

/// Bindings to the `performance` API
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm {
    use wasm_bindgen::prelude::*;

    use super::{Duration, Entry, MIN_MESSAGE_DURATION_MS, Track};

    // Chrome DevTools extensibility API: entries with this metadata get a custom track.
    const DATA_TYPE: &str = "track-entry";
    const TRACK_GROUP: &str = "IPC";

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(catch, js_namespace = performance, js_name = now)]
        fn performance_now() -> Result<f64, JsValue>;

        #[wasm_bindgen(catch, js_namespace = performance, js_name = measure)]
        fn performance_measure(name: &str, options: &JsValue) -> Result<JsValue, JsValue>;
    }

    /// Records an entry on the timeline when dropped, so early returns and cancelled futures
    /// are recorded too.
    pub(crate) struct Span {
        started: Option<(Track, Duration, Entry, f64)>,
    }

    /// Starts a span. `entry` is only evaluated where the timeline is available.
    pub(crate) fn span(track: Track, duration: Duration, entry: impl FnOnce() -> Entry) -> Span {
        Span {
            started: performance_now()
                .ok()
                .map(|start| (track, duration, entry(), start)),
        }
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let Some((track, duration, entry, start)) = self.started.take() else {
                return;
            };
            let Ok(now) = performance_now() else {
                return;
            };

            let end = match duration {
                Duration::Actual => now,
                Duration::AtLeastMessage => now.max(start + MIN_MESSAGE_DURATION_MS),
            };
            measure(track, &entry, start, end);
        }
    }

    /// Records `entry` from `start` to `end`, e.g. `performance.measure("RpcRequestMessage", {
    /// start, end, detail: { devtools: { dataType: "track-entry", trackGroup: "IPC", track:
    /// "Sent", properties: [["Destination", "DesktopMain"]] } } })`.
    fn measure(track: Track, entry: &Entry, start: f64, end: f64) {
        let properties = js_sys::Array::new();
        for (key, value) in &entry.properties {
            properties.push(&js_sys::Array::of2(&(*key).into(), &value.into()));
        }

        let devtools = object(&[
            ("dataType", DATA_TYPE.into()),
            ("trackGroup", TRACK_GROUP.into()),
            ("track", track_name(track).into()),
            ("properties", properties.into()),
        ]);
        let detail = object(&[("devtools", devtools)]);
        let options = object(&[
            ("start", start.into()),
            ("end", end.into()),
            ("detail", detail),
        ]);

        // Best effort: a rejected measure must not fail the IPC operation.
        let _ = performance_measure(&entry.name, &options);
    }

    fn track_name(track: Track) -> &'static str {
        match track {
            Track::Sent => "Sent",
            Track::Received => "Received",
            Track::Requests => "Requests",
            Track::Handlers => "Handlers",
            Track::Handshakes => "Handshakes",
        }
    }

    fn object(fields: &[(&str, JsValue)]) -> JsValue {
        let object = js_sys::Object::new();
        for (key, value) in fields {
            let _ = js_sys::Reflect::set(&object, &JsValue::from_str(key), value);
        }
        object.into()
    }
}

/// No-op span where the timeline is unavailable.
#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
pub(crate) struct Span;

#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
pub(crate) fn span(_track: Track, _duration: Duration, _entry: impl FnOnce() -> Entry) -> Span {
    Span
}
