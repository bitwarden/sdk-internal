//! The HKDF `info` that separates key-derivation purposes.

/// The HKDF `info` parameter used when deriving an [`crate::AccessTokenKey`] from an
/// [`crate::AccessTokenSeed`].
///
/// Distinct purposes derive distinct keys from the same seed. This crate defines no purposes of
/// its own: callers construct their own, typically one per kind of credential they build on top of
/// this crate's key material. The caller is responsible for:
///
/// - keeping every purpose string it defines unique among the others it defines, since two purposes
///   that collide derive the same key from the same seed, and
/// - never changing the string of a purpose once it has been used to mint issued credentials, since
///   that would silently change which key those credentials derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPurpose(&'static str);

impl KeyPurpose {
    /// Defines a new key-derivation purpose. See the type documentation for the uniqueness and
    /// stability requirements the caller must uphold for the `info` string it passes.
    pub const fn new(info: &'static str) -> Self {
        Self(info)
    }

    /// The HKDF `info` string this purpose wraps.
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
