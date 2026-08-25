use bitwarden_managed_settings::ManagedSettingsClient;
use bitwarden_managed_settings_types::ManagementProfile;

/// UniFFI wrapper for [`ManagedSettingsClient`].
///
/// The host application constructs one of these at boot, acquires a management profile from the
/// operating system's Unified Endpoint Management channel, and pushes it in with
/// [`update_profile`](ManagedSettingsBindingClient::update_profile).
#[derive(uniffi::Object)]
pub struct ManagedSettingsBindingClient(pub(crate) ManagedSettingsClient);

impl Default for ManagedSettingsBindingClient {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl ManagedSettingsBindingClient {
    /// Fresh handle with no active profile.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(ManagedSettingsClient::new())
    }

    /// Replace the active profile. Clear the profile with `None`.
    pub fn update_profile(&self, profile: Option<ManagementProfile>) {
        self.0.update_profile(profile);
    }

    /// Returns `true` if `key` is present in the active profile.
    pub fn is_managed(&self, key: String) -> bool {
        self.0.is_managed(key)
    }

    /// Raw JSON-encoded value for `key`, if a value is present.
    pub fn get(&self, key: String) -> Option<String> {
        self.0.get(key)
    }
}
