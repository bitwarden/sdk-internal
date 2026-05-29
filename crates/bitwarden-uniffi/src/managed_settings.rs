//! UniFFI sub-client for the managed-settings (IT-admin-forced settings) domain.

use bitwarden_managed_settings::{ManagedSettingsClient, ManagementProfile};

/// Mobile-facing handle for managed-settings operations. Wraps the
/// pure-Rust [`ManagedSettingsClient`] returned by `ClientExt`.
#[derive(uniffi::Object)]
pub struct ManagedSettingsBindingClient(pub(crate) ManagedSettingsClient);

#[uniffi::export]
impl ManagedSettingsBindingClient {
    /// Replace the active managed-settings profile.
    ///
    /// `None` clears the profile, restoring "no admin overrides" behavior.
    pub fn update_profile(&self, profile: Option<ManagementProfile>) {
        self.0.update_profile(profile);
    }

    /// Returns `true` if `key` is present in the active profile.
    pub fn is_managed(&self, key: String) -> bool {
        self.0.is_managed(key)
    }

    /// Returns the raw JSON-encoded string stored under `key`, if any.
    pub fn get(&self, key: String) -> Option<String> {
        self.0.get(key)
    }
}
