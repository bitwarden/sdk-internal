//! Type-safe keys for settings storage.

use std::marker::PhantomData;

/// Register a type-safe settings key.
///
/// This macro is the primary way to create settings keys. It associates
/// a string key name with a value type at compile time.
///
/// # Example
/// ```rust
/// use bitwarden_state::register_setting_key;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppConfig {
///     theme: String,
///     auto_save: bool,
/// }
///
/// register_setting_key!(pub const CONFIG: AppConfig = "app_config");
/// ```
#[macro_export]
macro_rules! register_setting_key {
    ($vis:vis const $name:ident: $ty:ty = $key:literal) => {
        $vis const $name: $crate::settings::Key<$ty> = $crate::settings::Key::new($key);
    };
}

/// Type-safe key for settings storage.
///
/// Associates a string key name with a value type at compile time,
/// preventing type mismatches while maintaining ergonomic usage.
///
/// Use the [`register_setting_key!`](crate::register_setting_key) macro to create keys.
///
/// # Example
/// ```rust
/// use bitwarden_state::register_setting_key;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppConfig {
///     theme: String,
///     auto_save: bool,
/// }
///
/// register_setting_key!(pub const CONFIG: AppConfig = "app_config");
/// ```
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
