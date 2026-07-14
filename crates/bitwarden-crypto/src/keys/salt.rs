use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::CryptoError;

/// The salt used together with a user's password in a Key Derivation Function (KDF, see [`Kdf`](
/// crate::Kdf)) to derive a [`MasterKey`](crate::MasterKey).
///
/// This is a thin wrapper around a [`String`], not an encrypted or hashed value. Its only purpose
/// is to give the salt its own type, so that the compiler can catch mistakes such as passing a
/// salt where a password or raw email string was expected, or the reverse. Because
/// [`PartialEq`]/[`Eq`] are derived structurally, mixing up two [`Salt`]s (for example a stale
/// salt with a fresh one) is still possible - this type only protects against confusing a
/// [`Salt`] with a completely unrelated [`String`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Salt(#[cfg_attr(feature = "wasm", tsify(type = "string"))] String);

impl Salt {
    /// Returns the salt as a string slice, e.g. to pass into a KDF function.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constructs a [`Salt`] from untrusted input, cleaning it by trimming whitespace and
    /// lowercasing it, and rejecting the value if the cleaned result is empty. Use this
    /// constructor for salts originating outside the SDK (e.g. values crossing the FFI
    /// boundary).
    pub fn new(value: &str) -> Result<Self, CryptoError> {
        let cleaned = value.trim().to_lowercase();
        if cleaned.is_empty() {
            return Err(CryptoError::InvalidSalt);
        }
        Ok(Self(cleaned))
    }
}

impl From<String> for Salt {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Salt {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl std::fmt::Display for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_and_from_str_are_equivalent() {
        assert_eq!(
            Salt::from("salt-value"),
            Salt::from("salt-value".to_string())
        );
    }

    #[test]
    fn as_str_returns_inner_value() {
        let salt = Salt::from("salt-value");
        assert_eq!(salt.as_str(), "salt-value");
    }

    #[test]
    fn display_matches_inner_value() {
        let salt = Salt::from("salt-value");
        assert_eq!(salt.to_string(), "salt-value");
    }

    #[test]
    fn serializes_as_a_plain_string() {
        let salt = Salt::from("salt-value");
        let serialized = serde_json::to_string(&salt).unwrap();
        assert_eq!(serialized, "\"salt-value\"");

        let deserialized: Salt = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, salt);
    }

    #[test]
    fn new_trims_and_lowercases_input() {
        let salt = Salt::new("  Salt-Value ").unwrap();
        assert_eq!(salt, Salt::from("salt-value"));
    }

    #[test]
    fn new_rejects_empty_input() {
        assert!(matches!(Salt::new(""), Err(CryptoError::InvalidSalt)));
    }

    #[test]
    fn new_rejects_whitespace_only_input() {
        assert!(matches!(Salt::new("   "), Err(CryptoError::InvalidSalt)));
    }
}
