#![allow(missing_docs)]

use std::fmt::Display;

use bitwarden_error::{bitwarden_error, flat_error::FlatError};
#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[test]
fn variant_for_basic_enum() {
    #[bitwarden_error(flat)]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    impl Display for SimpleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let foo = SimpleError::Foo;
    let bar = SimpleError::Bar;
    let baz = SimpleError::Baz;

    assert_eq!(foo.error_variant(), "Foo");
    assert_eq!(bar.error_variant(), "Bar");
    assert_eq!(baz.error_variant(), "Baz");
}

#[test]
fn variant_for_enum_with_fields() {
    #[allow(dead_code)]
    #[bitwarden_error(flat)]
    enum ComplexError {
        Foo(String),
        Bar { x: i32, y: i32 },
        Baz(bool, bool),
    }
    impl Display for ComplexError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let foo = ComplexError::Foo("hello".to_string());
    let bar = ComplexError::Bar { x: 1, y: 2 };
    let baz = ComplexError::Baz(true, true);

    assert_eq!(foo.error_variant(), "Foo");
    assert_eq!(bar.error_variant(), "Bar");
    assert_eq!(baz.error_variant(), "Baz");
}

#[test]
#[cfg(feature = "wasm")]
fn variant_names_for_enum() {
    #[allow(dead_code)]
    #[bitwarden_error(flat)]
    enum SimpleEnum {
        Foo,
        Bar,
        Baz,
    }
    impl Display for SimpleEnum {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    // TODO: Not sure how to test this yet
    // let types = TS_TYPES_SimpleError;
    // assert_eq!(
    //     types,
    //     r#"
    //         export const TS_TYPES_SimpleError = "<TODO>";
    //     "#
    // );
}

#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
fn converts_to_js_error() {
    use bitwarden_error::wasm::SdkJsError;
    use wasm_bindgen::JsValue;

    #[bitwarden_error(flat)]
    enum FlatEnum {
        Foo,
        Bar,
        Baz,
    }
    impl Display for FlatEnum {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let simple = FlatEnum::Baz;
    let js_value: JsValue = simple.into();

    let js_error = SdkJsError::from(js_value);
    assert_eq!(js_error.name(), "FlatEnum");
    assert_eq!(js_error.message(), "This is an error");
    assert_eq!(js_error.variant(), "Baz");
}

#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
fn outputs_different_name_when_given_export_as() {
    use bitwarden_error::wasm::SdkJsError;
    use wasm_bindgen::JsValue;

    #[bitwarden_error(flat, export_as = "SomeOtherEnum")]
    enum FlatEnum {
        Foo,
        Bar,
        Baz,
    }
    impl Display for FlatEnum {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let simple = FlatEnum::Baz;
    let js_value: JsValue = simple.into();

    let js_error = SdkJsError::from(js_value);
    assert_eq!(js_error.name(), "SomeOtherEnum");
    assert_eq!(js_error.message(), "This is an error");
    assert_eq!(js_error.variant(), "Baz");
}
