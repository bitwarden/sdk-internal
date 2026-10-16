//! Type-safe keys for persisted values storage.

use super::Internal;
use crate::Persist;

/// Register a type-safe persisted value key.
///
/// This macro is the primary way to create persisted value keys. It associates
/// a string key name with a value type at compile time.
///
/// **Important:** The key name must be globally unique across the entire application.
/// Using the same key name for different persisted values will cause conflicts. It may contain
/// only ASCII letters and underscores, which is checked at compile time.
///
/// # Example
/// ```rust
/// use bitwarden_state::register_persisted_value;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppConfig {
///     theme: String,
///     auto_save: bool,
/// }
///
/// register_persisted_value!(CONFIG: AppConfig = "app_config");
/// ```
#[macro_export]
macro_rules! register_persisted_value {
    ($(#[$meta:meta])* $vis:vis $name:ident: $ty:ty = $key:literal) => {
        // The key is a marker type named like a constant, and is never constructed.
        $(#[$meta])*
        #[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
        #[derive(Debug, Clone, Copy)]
        $vis struct $name {}

        const _: () = {
            impl $crate::persisted_value::___internal::Internal for $name {}
            impl $crate::persisted_value::PersistedValueKey for $name {
                const NAME: &'static str = $key;
                type Value = $ty;
            }
            assert!(
                $crate::repository::validate_registry_name($key),
                concat!(
                    "Persisted value key '",
                    $key,
                    "' must contain only alphabetic characters and underscores"
                )
            )
        };
    };
}

/// Type-safe key for persisted values storage.
///
/// Associates a string key name with a value type at compile time,
/// preventing type mismatches while maintaining ergonomic usage.
///
/// Use the [`register_persisted_value!`](crate::register_persisted_value) macro to create keys.
///
/// # Example
/// ```rust
/// use bitwarden_state::register_persisted_value;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppConfig {
///     theme: String,
///     auto_save: bool,
/// }
///
/// register_persisted_value!(CONFIG: AppConfig = "app_config");
/// ```
pub trait PersistedValueKey: Internal + Send + Sync + 'static {
    /// The key name the value is stored under.
    const NAME: &'static str;

    /// The type stored under this key.
    type Value: Persist;
}
