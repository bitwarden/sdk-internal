/// A wrapper type that marks the inner value as secret. This is used to prevent accidental logging
/// of secrets by overriding the `Debug` and `Display` implementations to redact the value. This
/// redaction can be bypassed by enabling the `dangerous-crypto-debug` feature.
pub struct Sensitive<T>(pub(crate) T);

/// A trait for types that can expose their inner secret value. This is implemented for
/// `Sensitive<T>` and can be implemented for other wrapper types as needed. The `expose` and
/// `expose_owned` methods are intentionally explicit and require justification in comments to
/// prevent accidental misuse.
pub trait ExposeSensitive {
    /// The type of the inner value that is being wrapped. This is used to define the return type of
    /// the `expose` and `expose_owned` methods.
    type Exposed;

    /// Explicitly borrow the secret value. This exposes the secret to logging. This should be used
    /// exactly only when interacting with APIs we do not control. Each usage of `expose` MUST have
    /// a comment justifying why it is necessary and acknowledging that the appropriate checks have
    /// been performed.
    fn expose(&self) -> &Self::Exposed;

    /// Consume the wrapper and return the inner value. This exposes the secret to logging. This
    /// should be used exactly only when interacting with APIs we do not control. Each usage of
    /// `expose` MUST have a comment justifying why it is necessary and acknowledging that the
    /// appropriate checks have been performed.
    fn expose_owned(self) -> Self::Exposed;
}

impl<T> ExposeSensitive for Sensitive<T> {
    type Exposed = T;

    /// Explicitly borrow the wrapped value. This exposes the secret to logging. This should
    /// be used exactly only when interacting with APIs we do not control. Each usage of expose
    /// MUST have a comment justifying why it is necessary and acknowledging that the appropriate
    /// checks have been performed.
    /// ```
    /// use bitwarden_sensitive_value::{ExposeSensitive, Sensitive};
    /// # fn pbkdf2(_password: &[u8], _salt: &[u8], _rounds: u32) -> [u8; 32] { [0u8; 32] }
    /// fn hash_password(password: &Sensitive<String>) -> [u8; 32] {
    ///    // EXPOSE: We need to pass the password to pbkdf2, because `pbkdf2` does not support the
    ///    // sensitive type and is an external crate. It is safe to do so because the library does
    ///    // not log data.
    ///    let exposed = password.expose();
    ///    pbkdf2(exposed.as_bytes(), b"salt", 100_000)
    /// }
    /// ```
    fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the inner value. This exposes the secret to logging.
    fn expose_owned(self) -> T {
        self.0
    }
}

impl<T> PartialEq for Sensitive<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T> Clone for Sensitive<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: serde::Serialize> serde::Serialize for Sensitive<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Sensitive<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(T::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wraps_value_and_expose_returns_it() {
        let sensitive = Sensitive::from(42u32);
        assert_eq!(sensitive.expose(), &42);
        assert_eq!(sensitive.expose_owned(), 42);
    }

    #[test]
    fn from_str_creates_sensitive_string() {
        let sensitive: Sensitive<String> = Sensitive::from("secret");
        assert_eq!(sensitive.expose(), "secret");
    }

    #[test]
    fn partial_eq_compares_inner_values() {
        assert_eq!(Sensitive::from(1u32), Sensitive::from(1u32));
        assert_ne!(Sensitive::from(1u32), Sensitive::from(2u32));
    }

    #[cfg(not(feature = "dangerous-crypto-debug"))]
    #[test]
    fn debug_is_redacted() {
        let sensitive = Sensitive::from("secret".to_string());
        assert_eq!(format!("{sensitive:?}"), "[REDACTED]");
    }

    #[cfg(not(feature = "dangerous-crypto-debug"))]
    #[test]
    fn display_is_redacted() {
        let sensitive = Sensitive::from("secret".to_string());
        assert_eq!(format!("{sensitive}"), "[REDACTED]");
    }

    #[test]
    fn serde_json_round_trips_transparently() {
        let sensitive = Sensitive::from("secret".to_string());

        let serialized = serde_json::to_string(&sensitive).unwrap();
        assert_eq!(serialized, "\"secret\"");

        let deserialized: Sensitive<String> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, sensitive);
    }
}
