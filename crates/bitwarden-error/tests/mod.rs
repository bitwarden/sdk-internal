use bitwarden_error::metadata::{AsErrorMetadata, ErrorMetadata};

#[test]
fn variant_for_basic_enum() {
    enum SimpleError {
        Foo,
        Bar,
        Baz,
    }

    impl AsErrorMetadata for SimpleError {
        fn as_metadata(&self) -> ErrorMetadata {
            match self {
                SimpleError::Foo => ErrorMetadata {
                    name: "SimpleError::Foo",
                    message: "An error occurred in the Foo variant",
                },
                SimpleError::Bar => ErrorMetadata {
                    name: "SimpleError::Bar",
                    message: "An error occurred in the Bar variant",
                },
                SimpleError::Baz => ErrorMetadata {
                    name: "SimpleError::Baz",
                    message: "An error occurred in the Baz variant",
                },
            }
        }
    }

    let foo = SimpleError::Foo;
    let bar = SimpleError::Bar;
    let baz = SimpleError::Baz;

    assert_eq!(foo.as_metadata().name, "SimpleError::Foo");
    assert_eq!(bar.as_metadata().name, "SimpleError::Bar");
    assert_eq!(baz.as_metadata().name, "SimpleError::Baz");
}
