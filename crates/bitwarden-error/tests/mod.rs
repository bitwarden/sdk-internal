use bitwarden_error::BitwardenError;

#[test]
fn variant_for_basic_enum() {
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    impl BitwardenError for SimpleError {
        fn variant(&self) -> &'static str {
            match self {
                SimpleError::Foo => "SimpleError::Foo",
                SimpleError::Bar => "SimpleError::Bar",
                SimpleError::Baz => "SimpleError::Baz",
            }
        }

        fn message(&self) -> &'static str {
            todo!()
        }
    }

    let foo = SimpleError::Foo;
    let bar = SimpleError::Bar;
    let baz = SimpleError::Baz;

    assert_eq!(foo.variant(), "SimpleError::Foo");
    assert_eq!(bar.variant(), "SimpleError::Bar");
    assert_eq!(baz.variant(), "SimpleError::Baz");
}
