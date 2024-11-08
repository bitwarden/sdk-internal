use bitwarden_error::prelude::*;

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

    assert_eq!(foo.error_variant(), "SimpleError::Foo");
    assert_eq!(bar.error_variant(), "SimpleError::Bar");
    assert_eq!(baz.error_variant(), "SimpleError::Baz");
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

    assert_eq!(foo.error_variant(), "ComplexError::Foo");
    assert_eq!(bar.error_variant(), "ComplexError::Bar");
    assert_eq!(baz.error_variant(), "ComplexError::Baz");
}

#[test]
fn variant_for_struct() {
    #[derive(Debug)]
    #[bitwarden_error(flat)]
    struct SimpleStruct;

    impl ToString for SimpleStruct {
        fn to_string(&self) -> String {
            format!("{:?}", self)
        }
    }

    let simple = SimpleStruct;

    assert_eq!(simple.error_variant(), "SimpleStruct");
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

#[test]
#[cfg(feature = "wasm")]
fn variant_names_for_struct() {
    #[allow(dead_code)]
    #[derive(Debug)]
    #[bitwarden_error(flat)]
    struct SimpleStruct;

    impl ToString for SimpleStruct {
        fn to_string(&self) -> String {
            format!("{:?}", self)
        }
    }

    // TODO: Not sure how to test this yet
    // let types = TS_TYPES_SimpleStruct;
    // assert_eq!(
    //     types,
    //     r#"
    //         export const TS_TYPES_SimpleStruct = "<TODO>";
    //     "#
    // );
}
