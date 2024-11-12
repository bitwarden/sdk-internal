use bitwarden_error::prelude::*;
#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[test]
fn variant_for_basic_enum() {
    #[derive(Debug)]
    #[bitwarden_error(flat)]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    impl ToString for SimpleError {
        fn to_string(&self) -> String {
            format!("{:?}", self)
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
    #[derive(Debug)]
    #[bitwarden_error(flat)]
    enum ComplexError {
        Foo(String),
        Bar { x: i32, y: i32 },
        Baz(bool, bool),
    }

    impl ToString for ComplexError {
        fn to_string(&self) -> String {
            format!("{:?}", self)
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
    #[derive(Debug)]
    #[bitwarden_error(flat)]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    impl ToString for SimpleError {
        fn to_string(&self) -> String {
            format!("{:?}", self)
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
    use wasm_bindgen::JsValue;

    #[derive(Debug, FlatError)]
    enum SomeError {
        Foo,
        Bar,
        Baz,
    }
    impl ToString for SomeError {
        fn to_string(&self) -> String {
            "This is an error".to_string()
        }
    }

    let simple = SomeError::Baz;
    let js_value: JsValue = simple.into();

    let js_error = SdkJsError::from(js_value);
    assert_eq!(js_error.name(), "SomeError");
    assert_eq!(js_error.message(), "This is an error");
    assert_eq!(js_error.variant(), "Baz");
}
