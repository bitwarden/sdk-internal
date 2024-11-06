use bitwarden_error::prelude::*;

#[test]
fn variant_for_basic_enum() {
    #[derive(Debug)]
    #[bitwarden_error]
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
    #[bitwarden_error]
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
    #[bitwarden_error]
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
fn variant_names_for_enum() {
    #[allow(dead_code)]
    #[derive(Debug)]
    #[bitwarden_error]
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

    assert_eq!(
        SimpleError::error_variants(),
        &["SimpleError::Foo", "SimpleError::Bar", "SimpleError::Baz"]
    );
}

#[test]
fn variant_names_for_struct() {
    #[derive(Debug)]
    #[bitwarden_error]
    struct SimpleStruct;

    impl ToString for SimpleStruct {
        fn to_string(&self) -> String {
            format!("{:?}", self)
        }
    }

    assert_eq!(SimpleStruct::error_variants(), &["SimpleStruct"]);
}
