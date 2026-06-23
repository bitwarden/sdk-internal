use crate::Sensitive;

/// A zero-copy view over a borrowed slice of secret bytes. Wrapping a `&[u8]` borrows the
/// underlying buffer instead of cloning it, so the wrapper is bound by the borrow's lifetime
/// `'a` and cannot outlive the data it points at. `Debug`/`Display` are redacted via the inner
/// [`Sensitive`].
///
/// For owned secret bytes (e.g. when deserializing, where borrowing is not possible) use
/// `Sensitive<Vec<u8>>` instead.
pub type SensitiveSlice<'a> = Sensitive<&'a [u8]>;

impl<'a, const N: usize> From<&'a [u8; N]> for SensitiveSlice<'a> {
    fn from(value: &'a [u8; N]) -> Self {
        Sensitive::from(value.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSensitive;

    #[test]
    fn from_borrows_and_expose_returns_slice() {
        let key_material = [0x42u8; 32];
        let secret: SensitiveSlice<'_> = Sensitive::from(key_material.as_slice());

        assert_eq!(*secret.expose(), key_material.as_slice());
        assert_eq!(secret.expose_owned(), key_material.as_slice());
        // The owner still holds the buffer; wrapping only borrowed it.
        assert_eq!(key_material.len(), 32);
    }

    #[test]
    fn partial_eq_compares_borrowed_bytes() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let c = [9u8, 9, 9];

        assert_eq!(Sensitive::from(a.as_slice()), Sensitive::from(b.as_slice()));
        assert_ne!(Sensitive::from(a.as_slice()), Sensitive::from(c.as_slice()));
    }

    #[test]
    fn from_array_ref_borrows_without_as_slice() {
        let key_material = [0x42u8; 13];
        let secret: SensitiveSlice<'_> = (&key_material).into();
        assert_eq!(secret.expose_owned(), key_material.as_slice());
    }

    #[cfg(not(feature = "dangerous-crypto-debug"))]
    #[test]
    fn debug_is_redacted() {
        let secret: SensitiveSlice<'_> = Sensitive::from([0x42u8; 4].as_slice());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn serde_json_serializes_as_byte_array() {
        let bytes = [1u8, 2, 3];
        let secret: SensitiveSlice<'_> = Sensitive::from(bytes.as_slice());

        let serialized = serde_json::to_string(&secret).unwrap();
        assert_eq!(serialized, "[1,2,3]");
    }
}
