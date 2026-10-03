//! Marks slow cryptographic operations (KDFs, RSA, ML-DSA) on the browser performance timeline.
//!
//! On WASM, each operation becomes a `performance.measure` entry carrying Chrome DevTools
//! extensibility metadata, so the DevTools Performance panel shows it in its own track:
//!
//! ```text
//!   ▾ Crypto
//!     Slow Crypto   [ Argon2id ]          [ RSA decrypt ]   [ ML-DSA sign ]
//! ```
//!
//! Other environments ignore the metadata and record a plain measure. Outside WASM the span
//! compiles to nothing. Recording is best effort and never affects the operation.

/// A slow cryptographic operation shown on the performance timeline.
#[derive(Clone, Copy)]
pub(crate) enum SlowCryptoOp {
    Pbkdf2,
    Argon2id,
    RsaKeyGeneration,
    RsaEncrypt,
    RsaDecrypt,
    MlDsaKeyGeneration,
    MlDsaSign,
    MlDsaVerify,
}

/// Measures a [`SlowCryptoOp`] from creation until drop.
pub(crate) struct SlowCryptoSpan {
    /// The operation and its `performance.now()` start time, if the timeline is available.
    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    entry: Option<(SlowCryptoOp, f64)>,
}

impl SlowCryptoSpan {
    /// Starts measuring `op`. Keep the returned guard alive for the duration of the operation.
    #[must_use]
    pub(crate) fn start(op: SlowCryptoOp) -> Self {
        #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
        {
            Self {
                entry: timeline::now().map(|start| (op, start)),
            }
        }

        #[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
        {
            let _ = op;
            Self {}
        }
    }
}

// Implemented on every target so call sites can end a span early with `drop(span)`.
impl Drop for SlowCryptoSpan {
    fn drop(&mut self) {
        #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
        {
            let Some((op, start)) = self.entry else {
                return;
            };
            timeline::measure(op, start);
        }
    }
}

/// Bindings to the `performance` global. Every call is caught, so a missing or restricted API
/// (e.g. no `performance` in the realm) never throws into Rust.
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod timeline {
    use wasm_bindgen::prelude::*;

    use super::SlowCryptoOp;

    // Chrome DevTools extensibility API: entries with this metadata get a custom track.
    const DATA_TYPE: &str = "track-entry";
    const TRACK_GROUP: &str = "Crypto";
    const TRACK: &str = "Slow Crypto";

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(catch, js_namespace = performance, js_name = now)]
        fn performance_now() -> Result<f64, JsValue>;

        #[wasm_bindgen(catch, js_namespace = performance, js_name = measure)]
        fn performance_measure(name: &str, options: &JsValue) -> Result<JsValue, JsValue>;
    }

    pub(super) fn now() -> Option<f64> {
        performance_now().ok()
    }

    /// Records `op` from `start` until now, e.g. `performance.measure("Argon2id", { start, end,
    /// detail: { devtools: { dataType: "track-entry", trackGroup: "Crypto", track: "Slow Crypto" }
    /// } })`.
    pub(super) fn measure(op: SlowCryptoOp, start: f64) {
        let Some(end) = now() else {
            return;
        };

        let devtools = object(&[
            ("dataType", DATA_TYPE.into()),
            ("trackGroup", TRACK_GROUP.into()),
            ("track", TRACK.into()),
        ]);
        let detail = object(&[("devtools", devtools)]);
        let options = object(&[
            ("start", start.into()),
            ("end", end.into()),
            ("detail", detail),
        ]);

        // Best effort: a rejected measure must not fail the cryptographic operation.
        let _ = performance_measure(name(op), &options);
    }

    fn name(op: SlowCryptoOp) -> &'static str {
        match op {
            SlowCryptoOp::Pbkdf2 => "PBKDF2",
            SlowCryptoOp::Argon2id => "Argon2id",
            SlowCryptoOp::RsaKeyGeneration => "RSA key generation",
            SlowCryptoOp::RsaEncrypt => "RSA encrypt",
            SlowCryptoOp::RsaDecrypt => "RSA decrypt",
            SlowCryptoOp::MlDsaKeyGeneration => "ML-DSA key generation",
            SlowCryptoOp::MlDsaSign => "ML-DSA sign",
            SlowCryptoOp::MlDsaVerify => "ML-DSA verify",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_outside_wasm_is_a_no_op() {
        let span = SlowCryptoSpan::start(SlowCryptoOp::Argon2id);
        drop(span);
    }
}
