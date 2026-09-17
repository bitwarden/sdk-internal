//! The browser backend: turns a [`TrackEntry`] into the `performance.measure()` call shape the
//! Chrome DevTools performance panel recognizes as a custom track entry.
//!
//! ```js
//! performance.measure(name, {
//!   start, end,
//!   detail: { devtools: { dataType: "track-entry", trackGroup, track, properties } },
//! });
//! ```

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use super::entry::{Instant, TrackEntry};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn js_performance_now() -> f64;

    /// Fails if the panel rejects the entry shape; the result is discarded because a missing
    /// measure must never affect the operation being measured.
    #[wasm_bindgen(js_namespace = performance, js_name = measure, catch)]
    fn js_performance_measure(name: &str, options: &JsValue) -> Result<JsValue, JsValue>;
}

pub(crate) fn performance_now() -> f64 {
    js_performance_now()
}

pub(crate) fn emit(entry: &TrackEntry, start: Instant, end: Instant) {
    let devtools = Object::new();
    set(&devtools, "dataType", &JsValue::from_str("track-entry"));
    set(&devtools, "trackGroup", &JsValue::from_str(entry.group));
    set(&devtools, "track", &JsValue::from_str(entry.track));
    if !entry.properties.is_empty() {
        set(&devtools, "properties", &properties_array(entry));
    }

    let detail = Object::new();
    set(&detail, "devtools", &devtools);

    let options = Object::new();
    set(&options, "start", &JsValue::from_f64(start.0));
    set(&options, "end", &JsValue::from_f64(end.0));
    set(&options, "detail", &detail);

    let _ = js_performance_measure(&entry.name, &options);
}

/// DevTools expects properties as an array of `[key, value]` pairs.
fn properties_array(entry: &TrackEntry) -> JsValue {
    let properties = Array::new();
    for (key, value) in &entry.properties {
        let pair = Array::new();
        pair.push(&JsValue::from_str(key));
        pair.push(&JsValue::from_str(value));
        properties.push(&pair);
    }
    properties.into()
}

fn set(target: &Object, key: &str, value: &JsValue) {
    // A failed property set can only mean the panel will ignore the entry, which is not worth
    // propagating to the caller.
    let _ = Reflect::set(target, &JsValue::from_str(key), value);
}
