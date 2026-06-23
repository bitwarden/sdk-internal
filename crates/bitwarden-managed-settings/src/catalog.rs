//! Hand-maintained registry of the dotted keys the SDK resolves itself.
//!
//! Plan B's clients-repo catalog CI check validates that the per-OS admin
//! schemas cover exactly these keys. The deferred `ApplyManagedOverride` derive
//! macro will generate this list from the trait impls; until then it is updated
//! by hand whenever a key is added to an `ApplyManagedOverride` impl.

/// Value type an admin supplies for a managed key, used by schema generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedKeyType {
    /// A boolean (`true`/`false`) value.
    Bool,
    /// An unsigned 8-bit integer value.
    U8,
    /// A UTF-8 string value.
    String,
}

/// A key the SDK consumes internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedKey {
    /// The dotted key string, e.g., "generator.password.length".
    pub key: &'static str,
    /// The value type this key expects.
    pub value_type: ManagedKeyType,
}

/// Every dotted key the SDK resolves itself (see the `ApplyManagedOverride` impls).
pub fn managed_keys() -> &'static [ManagedKey] {
    use ManagedKeyType::*;
    &[
        ManagedKey { key: "generator.password.lowercase", value_type: Bool },
        ManagedKey { key: "generator.password.uppercase", value_type: Bool },
        ManagedKey { key: "generator.password.numbers", value_type: Bool },
        ManagedKey { key: "generator.password.special", value_type: Bool },
        ManagedKey { key: "generator.password.avoidAmbiguous", value_type: Bool },
        ManagedKey { key: "generator.password.length", value_type: U8 },
        ManagedKey { key: "generator.password.minLowercase", value_type: U8 },
        ManagedKey { key: "generator.password.minUppercase", value_type: U8 },
        ManagedKey { key: "generator.password.minNumber", value_type: U8 },
        ManagedKey { key: "generator.password.minSpecial", value_type: U8 },
        ManagedKey { key: "generator.passphrase.numWords", value_type: U8 },
        ManagedKey { key: "generator.passphrase.wordSeparator", value_type: String },
        ManagedKey { key: "generator.passphrase.capitalize", value_type: Bool },
        ManagedKey { key: "generator.passphrase.includeNumber", value_type: Bool },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_namespaced() {
        let keys = managed_keys();
        let mut seen = std::collections::HashSet::new();
        for k in keys {
            assert!(seen.insert(k.key), "duplicate key {}", k.key);
            assert!(k.key.contains('.'), "key {} is not dotted", k.key);
        }
    }

    #[test]
    fn catalog_covers_the_generator_keys() {
        let keys = managed_keys();
        assert!(keys.iter().any(|k| k.key == "generator.password.length"));
        assert!(keys.iter().any(|k| k.key == "generator.passphrase.numWords"));
        assert_eq!(managed_keys().len(), 14, "catalog key count changed — update this count and the per-platform admin schemas together");
    }
}
