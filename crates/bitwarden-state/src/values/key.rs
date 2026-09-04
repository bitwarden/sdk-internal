//! Type-safe keys for value storage.

use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};

use super::Internal;

/// Declare a type-safe value key.
///
/// Emits a marker type and a legacy [`Key`] constant sharing one name, so both call styles resolve
/// against the same declaration:
///
/// ```rust,ignore
/// state().value::<CONFIG>()  // marker type, preferred
/// state().setting(CONFIG)    // Key constant, removed once callers migrate
/// ```
///
/// **Important:** The storage name must be globally unique across the entire application. Two keys
/// sharing a name silently alias their storage.
///
/// # Example
/// ```rust
/// use bitwarden_state::register_value_key;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// pub struct AppConfig {
///     theme: String,
///     auto_save: bool,
/// }
///
/// register_value_key!(pub CONFIG: AppConfig = "app_config");
/// ```
#[macro_export]
macro_rules! register_value_key {
    ($(#[$meta:meta])* $vis:vis $name:ident: $ty:ty = $key:literal) => {
        // The marker takes the key's name, so it is const-cased, and is only ever named in type
        // position, never constructed.
        $(#[$meta])*
        #[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
        #[derive(Debug, Clone, Copy)]
        $vis struct $name {}

        // Only one of the two spellings is used at any given call site.
        $(#[$meta])*
        #[allow(dead_code)]
        $vis const $name: $crate::values::Key<$ty> = $crate::values::Key::new($key);

        const _: () = {
            impl $crate::values::___internal::Internal for $name {}
            impl $crate::values::ValueKey for $name {
                const NAME: &'static str = $key;
                type Value = $ty;
            }
            assert!(
                $crate::repository::validate_registry_name($key),
                concat!(
                    "Value key '",
                    $key,
                    "' must contain only alphabetic characters and underscores"
                )
            )
        };
    };
}

/// The old spelling of [`register_value_key!`](crate::register_value_key). Removed once every
/// caller has migrated.
#[macro_export]
macro_rules! register_setting_key {
    ($(#[$meta:meta])* $vis:vis const $name:ident: $ty:ty = $key:literal) => {
        $crate::register_value_key!($(#[$meta])* $vis $name: $ty = $key);
    };
}

/// Identifies exactly one stored value: its storage name and the type stored under it.
///
/// Implemented by the marker type that
/// [`register_value_key!`](crate::register_value_key) emits — do not implement it manually.
pub trait ValueKey: Internal + Send + Sync + 'static {
    /// The storage name of the value. Must be unique across the application.
    const NAME: &'static str;

    /// The type stored under this key.
    type Value: Serialize + DeserializeOwned + Send + Sync + 'static;
}

/// Type-safe key for value storage.
///
/// Superseded by [`ValueKey`], which identifies a value by type and so can be injected with
/// `#[derive(FromClient)]`. Removed once every caller has migrated to
/// [`Value`](crate::Value).
#[derive(Debug, Clone, Copy)]
pub struct Key<T> {
    pub(crate) name: &'static str,
    _marker: PhantomData<T>,
}

impl<T> Key<T> {
    /// Create a new type-safe key with the given storage name.
    #[doc(hidden)]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _marker: PhantomData,
        }
    }
}
