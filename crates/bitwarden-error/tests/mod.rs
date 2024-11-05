use bitwarden_error::prelude::*;

#[test]
fn variant_for_basic_enum() {
    #[bitwarden_error]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
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
    #[bitwarden_error]
    enum ComplexError {
        Foo(String),
        Bar { x: i32, y: i32 },
        Baz(bool, bool),
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
    #[bitwarden_error]
    struct SimpleStruct;

    let simple = SimpleStruct;

    assert_eq!(simple.error_variant(), "SimpleStruct");
}

#[test]
fn variant_names_for_enum() {
    #[allow(dead_code)]
    #[bitwarden_error]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    assert_eq!(
        SimpleError::error_variants(),
        &["SimpleError::Foo", "SimpleError::Bar", "SimpleError::Baz"]
    );
}

#[test]
fn variant_names_for_struct() {
    #[bitwarden_error]
    struct SimpleStruct;

    assert_eq!(SimpleStruct::error_variants(), &["SimpleStruct"]);
}
