use bitwarden_error_macro::bitwarden_error;

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

    // assert_eq!(foo.variant(), "SimpleError::Foo");
    // assert_eq!(bar.variant(), "SimpleError::Bar");
    // assert_eq!(baz.variant(), "SimpleError::Baz");
}
