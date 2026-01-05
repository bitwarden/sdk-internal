//! Type-safe keys for settings storage.

use std::marker::PhantomData;

/// Type-safe key for settings storage.
///
/// Associates a string key name with a value type at compile time,
/// preventing type mismatches while maintaining ergonomic usage.
///
/// # Example
/// ```rust
/// use bitwarden_settings::{ClientSettingsExt, Key};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AuthState {
///     user_id: String,
///     token: String,
/// }
///
/// pub const AUTH: Key<AuthState> = Key::new("auth");
///
/// // Usage:
/// # async {
/// # let client: bitwarden_core::Client = todo!();
/// let auth_state: Option<AuthState> = client.settings().get(AUTH).await?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Key<T> {
    name: &'static str,
    _marker: PhantomData<T>,
}

impl<T> Key<T> {
    /// Create a new type-safe key with the given storage name.
    ///
    /// # Example
    /// ```rust
    /// use bitwarden_settings::Key;
    ///
    /// const MY_KEY: Key<String> = Key::new("my_setting");
    /// ```
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _marker: PhantomData,
        }
    }

    /// Get the string key name used for storage.
    pub const fn name(&self) -> &'static str {
        self.name
    }
}
