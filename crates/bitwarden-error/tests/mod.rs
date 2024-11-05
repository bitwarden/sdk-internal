use bitwarden_error::prelude::*;

#[test]
fn variant_for_basic_enum() {
    #[derive(AsErrorMetadata)]
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    let foo = SimpleError::Foo;
    let bar = SimpleError::Bar;
    let baz = SimpleError::Baz;

    assert_eq!(foo.as_metadata().name, "SimpleError::Foo");
    assert_eq!(bar.as_metadata().name, "SimpleError::Bar");
    assert_eq!(baz.as_metadata().name, "SimpleError::Baz");
}
