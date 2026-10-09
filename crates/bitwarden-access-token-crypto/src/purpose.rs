//! The HKDF `info` that separates key-derivation purposes.

/// The HKDF `info` that separates keys derived from the same [`crate::AccessTokenSeed`].
///
/// Callers define their own purposes. Each string must be unique (colliding purposes derive the
/// same key) and must never change once credentials are issued under it (they would derive a
/// different key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPurpose(&'static str);

impl KeyPurpose {
    /// Defines a purpose. See the type docs for the caller's obligations.
    pub const fn new(info: &'static str) -> Self {
        Self(info)
    }

    pub(crate) fn as_str(&self) -> &'static str {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_string_is_equal() {
        assert_eq!(KeyPurpose::new("a"), KeyPurpose::new("a"));
    }

    #[test]
    fn different_strings_are_not_equal() {
        assert_ne!(KeyPurpose::new("a"), KeyPurpose::new("b"));
    }
}
