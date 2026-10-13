//! Tests for `#[wasm_export]`.
#![cfg(feature = "wasm")]
#![allow(missing_docs)]

use bitwarden_ffi::{Ts, TsError, wasm_export};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}
bitwarden_ffi::impl_wire_record!(Point);

#[derive(Debug, PartialEq)]
pub struct MoveError;

impl From<MoveError> for JsValue {
    fn from(_: MoveError) -> Self {
        JsValue::from_str("MoveError")
    }
}

/// Crosses the ABI as an opaque handle, not via serde — it has no `Tsify` impl at all.
#[bitwarden_ffi::wasm_object]
pub struct Handle {
    _x: i32,
}

#[bitwarden_ffi::wasm_object]
pub struct Canvas;

#[wasm_export]
impl Canvas {
    /// Fallible, converts a parameter and the return value.
    pub fn translate(&self, point: Point, dx: i32) -> Result<Point, MoveError> {
        if dx < 0 {
            return Err(MoveError);
        }
        Ok(Point {
            x: point.x + dx,
            y: point.y,
        })
    }

    /// Converts a parameter but leaves the return value alone.
    pub fn area(&self, point: Point) -> Result<i32, MoveError> {
        Ok(point.x * point.y)
    }

    /// `Vec<T>` maps to `Vec<Ts<T>>` in both directions.
    pub fn flip_all(&self, points: Vec<Point>) -> Result<Vec<Point>, MoveError> {
        Ok(points
            .into_iter()
            .map(|p| Point { x: p.y, y: p.x })
            .collect())
    }

    /// `Option<T>` maps to `Option<Ts<T>>` in both directions.
    pub fn maybe_origin(&self, point: Option<Point>) -> Result<Option<Point>, MoveError> {
        Ok(point.map(|_| Point { x: 0, y: 0 }))
    }

    /// Nesting recurses to the leaf: `Ts` wraps the `Point`, not the `Vec`.
    pub fn maybe_all(&self, points: Option<Vec<Point>>) -> Result<Option<Vec<Point>>, MoveError> {
        Ok(points)
    }

    /// An infallible method still yields a fallible shim, because conversion can fail.
    pub fn double(&self, point: Point) -> Point {
        Point {
            x: point.x * 2,
            y: point.y * 2,
        }
    }

    /// Associated function: the shim calls `Self::…` rather than `self.…`.
    pub fn unit() -> Result<Point, MoveError> {
        Ok(Point { x: 1, y: 1 })
    }

    /// Associated function *with* parameters: the receiver slot is empty, so the parameter list
    /// must not start with a stray comma.
    pub fn scaled(point: Point, factor: i32) -> Result<Point, MoveError> {
        Ok(Point {
            x: point.x * factor,
            y: point.y * factor,
        })
    }

    /// The method's own `#[wasm_bindgen]` attributes are forwarded to the shim, so `js_name` is
    /// written exactly as it would be without this macro.
    #[wasm_bindgen(js_name = "originPoint")]
    pub fn origin(&self, point: Point) -> Result<Point, MoveError> {
        Ok(point)
    }

    /// Async methods keep their asyncness in the shim.
    #[allow(clippy::unused_async)]
    pub async fn translate_async(&self, point: Point) -> Result<Point, MoveError> {
        Ok(point)
    }

    /// A primitive parameter and return project onto themselves, so no `Ts` appears.
    pub fn label(&self, point: Point, name: String) -> Result<String, MoveError> {
        Ok(format!("{name}:{},{}", point.x, point.y))
    }

    /// A `#[wasm_object]` handle crosses as itself while a record beside it crosses as `Ts<T>`,
    /// decided by each type's own impl rather than by the macro. The `JsTokenProvider` case.
    pub fn with_handle(&self, handle: Handle, point: Point) -> Result<Point, MoveError> {
        let _ = handle;
        Ok(point)
    }

    /// The same in return position.
    pub fn make_handle(&self, point: Point) -> Result<Handle, MoveError> {
        Ok(Handle { _x: point.x })
    }

    /// A type whose wire form is itself still routes through `from_wire`/`to_wire`, so the shim is
    /// fallible even though `Ok` is the only reachable arm.
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    /// Nothing to convert in either direction, and the shim is fallible anyway. Special-casing this
    /// shape would add a second code path for a signature JavaScript cannot tell apart.
    pub fn reset(&self) {}

    /// A borrowed parameter is passed through untouched, but the shim is still fallible.
    pub fn measure(&self, handle: &Handle) -> i32 {
        handle._x
    }

    /// Private methods are not exported, matching wasm_bindgen.
    fn internal(&self, point: Point) -> Point {
        point
    }

    /// `#[wasm_only]` renames the method so Rust callers do not reach for it and marks it
    /// deprecated. JavaScript still sees it under its original name, via the shim.
    #[wasm_only(note = "Use `Canvas::translate`.")]
    pub fn js_only(&self, point: Point) -> Result<Point, MoveError> {
        Ok(point)
    }
}

/// Free functions are shimmed the same way; the shim calls the function by name.
#[wasm_export]
pub fn shift(point: Point, dx: i32) -> Result<Point, MoveError> {
    if dx < 0 {
        return Err(MoveError);
    }
    Ok(Point {
        x: point.x + dx,
        y: point.y,
    })
}

/// Macro arguments on a free function land on the shim's own `#[wasm_bindgen]`.
#[wasm_export(js_name = "shiftBack")]
pub fn shift_back(point: Point) -> Point {
    Point {
        x: point.x - 1,
        y: point.y,
    }
}

/// A free function is treated the same way as a method, fallible shim included.
#[wasm_export]
pub fn shout(msg: String) -> String {
    msg.to_uppercase()
}

// --- The original methods keep their plain Rust signatures ---
//
// This is the property that makes the macro usable on signatures shared with UniFFI: nothing below
// mentions `Ts`, and none of these calls would compile if the macro had rewritten them in place.

#[test]
fn original_methods_take_and_return_plain_rust_types() {
    let point = Point { x: 1, y: 2 };

    assert_eq!(
        Canvas.translate(point.clone(), 5).unwrap(),
        Point { x: 6, y: 2 }
    );
    assert_eq!(Canvas.area(point.clone()).unwrap(), 2);
    assert_eq!(
        Canvas.flip_all(vec![point.clone()]).unwrap(),
        vec![Point { x: 2, y: 1 }]
    );
    assert_eq!(
        Canvas.maybe_origin(Some(point.clone())).unwrap(),
        Some(Point { x: 0, y: 0 })
    );
    assert_eq!(
        Canvas.maybe_all(Some(vec![point.clone()])).unwrap(),
        Some(vec![point.clone()])
    );
    assert_eq!(Canvas.double(point.clone()), Point { x: 2, y: 4 });
    assert_eq!(Canvas::unit().unwrap(), Point { x: 1, y: 1 });
    assert_eq!(
        Canvas::scaled(point.clone(), 3).unwrap(),
        Point { x: 3, y: 6 }
    );
    assert_eq!(Canvas.echo("hi".to_owned()), "hi");
    Canvas.reset();
    assert_eq!(Canvas.measure(&Handle { _x: 7 }), 7);
    assert_eq!(Canvas.internal(point.clone()), Point { x: 1, y: 2 });

    assert_eq!(shift(point.clone(), 5).unwrap(), Point { x: 6, y: 2 });
    assert_eq!(shift_back(point), Point { x: 0, y: 2 });
    assert_eq!(shout("hi".to_owned()), "HI");
}

#[test]
fn original_method_still_reports_its_own_error() {
    assert_eq!(Canvas.translate(Point { x: 0, y: 0 }, -1), Err(MoveError));
}

// --- The generated shims have the expected wire signatures ---
//
// Coercing to a function pointer asserts the generated signature exactly: a mismatch in the wire
// type, the error type, or the receiver fails to compile.

#[test]
#[allow(clippy::type_complexity)]
fn shims_wrap_marked_values_in_ts() {
    let _: fn(&Canvas, Ts<Point>, i32) -> Result<Ts<Point>, TsError<MoveError>> =
        Canvas::__wasm_ts_translate;

    // Unmarked return stays as-is.
    let _: fn(&Canvas, Ts<Point>) -> Result<i32, TsError<MoveError>> = Canvas::__wasm_ts_area;

    // Vec<T> becomes Vec<Ts<T>>, not Ts<Vec<T>>.
    let _: fn(&Canvas, Vec<Ts<Point>>) -> Result<Vec<Ts<Point>>, TsError<MoveError>> =
        Canvas::__wasm_ts_flip_all;

    let _: fn(&Canvas, Option<Ts<Point>>) -> Result<Option<Ts<Point>>, TsError<MoveError>> =
        Canvas::__wasm_ts_maybe_origin;

    // Infallible method: TsError's default parameter, so Conversion is the only variant.
    let _: fn(&Canvas, Ts<Point>) -> Result<Ts<Point>, TsError> = Canvas::__wasm_ts_double;

    let _: fn() -> Result<Ts<Point>, TsError<MoveError>> = Canvas::__wasm_ts_unit;
    let _: fn(Ts<Point>, i32) -> Result<Ts<Point>, TsError<MoveError>> = Canvas::__wasm_ts_scaled;

    // Inference boundary: the DTO is wrapped, the primitives on either side are not.
    let _: fn(&Canvas, Ts<Point>, String) -> Result<String, TsError<MoveError>> =
        Canvas::__wasm_ts_label;

    // Overrides win over inference, in each direction: the handle stays bare, the DTO is wrapped.
    let _: fn(&Canvas, Handle, Ts<Point>) -> Result<Ts<Point>, TsError<MoveError>> =
        Canvas::__wasm_ts_with_handle;
    let _: fn(&Canvas, Ts<Point>) -> Result<Handle, TsError<MoveError>> =
        Canvas::__wasm_ts_make_handle;

    // Nested containers keep their shape, with Ts at the leaf.
    let _: fn(
        &Canvas,
        Option<Vec<Ts<Point>>>,
    ) -> Result<Option<Vec<Ts<Point>>>, TsError<MoveError>> = Canvas::__wasm_ts_maybe_all;

    // Nothing can fail in either direction, and the shim is fallible regardless: one code path
    // for every method, and a `Result` JavaScript cannot tell apart from a bare return.
    let _: fn(&Canvas) -> Result<(), TsError> = Canvas::__wasm_ts_reset;
    let _: fn(&Canvas, &Handle) -> Result<i32, TsError> = Canvas::__wasm_ts_measure;

    // A type whose wire form is itself: no `Ts`, but still routed through `from_wire`/`to_wire`,
    // so the shim is fallible. `Ok` is the only reachable arm, and the `.d.ts` is unchanged.
    let _: fn(&Canvas, String) -> Result<String, TsError> = Canvas::__wasm_ts_echo;

    // #[wasm_only] still gets a shim, named after the original method.
    let _: fn(&Canvas, Ts<Point>) -> Result<Ts<Point>, TsError<MoveError>> =
        Canvas::__wasm_ts_js_only;

    // Free functions shim to a sibling function rather than into a generated impl block.
    let _: fn(Ts<Point>, i32) -> Result<Ts<Point>, TsError<MoveError>> = __wasm_ts_shift;
    let _: fn(Ts<Point>) -> Result<Ts<Point>, TsError> = __wasm_ts_shift_back;
    let _: fn(String) -> Result<String, TsError> = __wasm_ts_shout;
}

/// `#[wasm_only]` renames the original out of the way; the shim keeps the JS name.
#[test]
#[allow(deprecated)]
fn wasm_only_method_is_renamed() {
    assert_eq!(
        Canvas.__wasm_only_js_only(Point { x: 1, y: 2 }).unwrap(),
        Point { x: 1, y: 2 }
    );
}

// --- Runtime conversion behaviour, which only exists on wasm ---

#[cfg(target_arch = "wasm32")]
mod runtime {
    use tsify::serde_wasm_bindgen;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    fn ts_point(value: &JsValue) -> Ts<Point> {
        Ts::new_unchecked(value.clone())
    }

    #[wasm_bindgen_test]
    fn round_trips_a_valid_value() {
        let js = serde_wasm_bindgen::to_value(&Point { x: 1, y: 2 }).unwrap();
        let out = Canvas.__wasm_ts_translate(ts_point(&js), 5).unwrap();
        assert_eq!(out.to_rust().unwrap(), Point { x: 6, y: 2 });
    }

    /// The regression test for tsify#65: a value JavaScript cannot supply correctly has to come
    /// back as an `Err`. Under `#[tsify(from_wasm_abi)]` this path called
    /// `wasm_bindgen::throw_str` from inside `from_abi`, unwinding past the wasm frames without
    /// running destructors and leaking on every call.
    #[wasm_bindgen_test]
    fn malformed_input_is_an_error_not_a_throw() {
        let js = JsValue::from_str("not a point");
        let result = Canvas.__wasm_ts_translate(ts_point(&js), 5);
        assert!(matches!(result, Err(TsError::Conversion(_))));
    }

    /// The method's own error still travels as itself, not as a conversion error.
    #[wasm_bindgen_test]
    fn inner_error_is_preserved() {
        let js = serde_wasm_bindgen::to_value(&Point { x: 1, y: 2 }).unwrap();
        let result = Canvas.__wasm_ts_translate(ts_point(&js), -1);
        assert!(matches!(result, Err(TsError::Inner(MoveError))));
    }

    #[wasm_bindgen_test]
    fn converts_every_element_of_a_vec() {
        let js = serde_wasm_bindgen::to_value(&Point { x: 1, y: 2 }).unwrap();
        let out = Canvas
            .__wasm_ts_flip_all(vec![ts_point(&js), ts_point(&js)])
            .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].to_rust().unwrap(), Point { x: 2, y: 1 });
    }

    /// A bad element anywhere in a `Vec` fails the whole call rather than being skipped.
    #[wasm_bindgen_test]
    fn a_bad_vec_element_fails_the_call() {
        let good = serde_wasm_bindgen::to_value(&Point { x: 1, y: 2 }).unwrap();
        let bad = JsValue::from_str("not a point");
        let result = Canvas.__wasm_ts_flip_all(vec![ts_point(&good), ts_point(&bad)]);
        assert!(matches!(result, Err(TsError::Conversion(_))));
    }

    #[wasm_bindgen_test]
    fn none_is_not_a_conversion_failure() {
        let out = Canvas.__wasm_ts_maybe_origin(None).unwrap();
        assert!(out.is_none());
    }
}
