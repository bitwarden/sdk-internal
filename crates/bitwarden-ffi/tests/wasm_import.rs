#![allow(missing_docs)]

use bitwarden_ffi::wasm_import;

// --- Test: a block of imports compiles and its types are usable from Rust ---

#[wasm_import]
extern "C" {
    #[wasm_bindgen(js_name = Date)]
    pub type JsDate;

    #[wasm_bindgen(method, js_name = getTime)]
    pub fn get_time(this: &JsDate) -> f64;
}

#[allow(dead_code)]
fn time_of(date: &JsDate) -> f64 {
    date.get_time()
}

#[cfg(feature = "wasm")]
#[test]
fn an_imported_type_implements_the_wire_traits() {
    fn crosses_as_itself<T: bitwarden_ffi::FromWasm<Wire = T> + bitwarden_ffi::ToWasm<Wire = T>>() {
    }
    crosses_as_itself::<JsDate>();
}

// --- Test: a `catch` import takes Rust types, converting them in a generated wrapper ---

#[cfg(feature = "wasm")]
mod wrapped {
    use serde::{Deserialize, Serialize};
    use tsify::Tsify;
    use wasm_bindgen::JsValue;

    use super::*;

    // Only the wasm32 test calls the import.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    #[derive(Tsify, Serialize, Deserialize)]
    pub struct Point {
        pub x: i32,
        pub y: i32,
    }
    bitwarden_ffi::impl_wire_record!(Point);

    #[wasm_import]
    extern "C" {
        #[wasm_bindgen(catch, js_namespace = JSON)]
        pub fn stringify(value: Point) -> Result<JsValue, JsValue>;

        #[wasm_bindgen(catch, js_namespace = JSON)]
        pub fn parse(text: &str) -> Result<Point, JsValue>;
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn converts_the_argument_before_calling_javascript() {
        let json = stringify(Point { x: 1, y: 2 }).unwrap();
        assert_eq!(json.as_string().as_deref(), Some(r#"{"x":1,"y":2}"#));
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn converts_the_return_value_after_calling_javascript() {
        let point = parse(r#"{"x":1,"y":2}"#).unwrap();
        assert_eq!((point.x, point.y), (1, 2));

        assert!(parse(r#"{"x":"one"}"#).is_err());
    }
}
