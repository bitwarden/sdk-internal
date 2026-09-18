//! The browser backend: turns an event into the `performance.measure()` call shape the Chrome
//! DevTools performance panel recognizes as a custom track entry.
//!
//! ```js
//! performance.measure(name, {
//!   start, end,
//!   detail: { devtools: { dataType: "track-entry", trackGroup, track, properties } },
//! });
//! ```

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use crate::{descriptor::PerformanceEventDescriptor, timeline::Instant};

const TRACK_ENTRY_DATA_TYPE: &str = "track-entry";
const MARKER_DATA_TYPE: &str = "marker";

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn js_performance_now() -> f64;

    /// Fails if the panel rejects the entry shape; the result is discarded because a missing
    /// measure must never affect the operation being measured.
    #[wasm_bindgen(js_namespace = performance, js_name = measure, catch)]
    fn js_performance_measure(name: &str, options: &JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = performance, js_name = mark, catch)]
    fn js_performance_mark(name: &str, options: &JsValue) -> Result<JsValue, JsValue>;
}

pub(crate) fn performance_now() -> f64 {
    js_performance_now()
}

pub(crate) fn measure(
    entry_name: &str,
    descriptor: &PerformanceEventDescriptor,
    start: Instant,
    end: Instant,
) {
    let devtools = devtools_detail(TRACK_ENTRY_DATA_TYPE);
    set(
        &devtools,
        "trackGroup",
        &JsValue::from_str(&descriptor.namespace),
    );
    set(&devtools, "track", &JsValue::from_str(&descriptor.category));
    if !descriptor.properties.is_empty() {
        set(&devtools, "properties", &properties_array(descriptor));
    }

    let options = Object::new();
    set(&options, "start", &JsValue::from_f64(start.0));
    set(&options, "end", &JsValue::from_f64(end.0));
    set(&options, "detail", &detail(&devtools));

    let _ = js_performance_measure(entry_name, &options);
}

pub(crate) fn mark(name: &str) {
    let options = Object::new();
    set(
        &options,
        "detail",
        &detail(&devtools_detail(MARKER_DATA_TYPE)),
    );

    let _ = js_performance_mark(name, &options);
}

fn devtools_detail(data_type: &str) -> Object {
    let devtools = Object::new();
    set(&devtools, "dataType", &JsValue::from_str(data_type));
    devtools
}

fn detail(devtools: &Object) -> Object {
    let detail = Object::new();
    set(&detail, "devtools", devtools);
    detail
}

/// DevTools expects properties as an array of `[key, value]` pairs.
fn properties_array(descriptor: &PerformanceEventDescriptor) -> JsValue {
    let properties = Array::new();
    for (key, value) in &descriptor.properties {
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
