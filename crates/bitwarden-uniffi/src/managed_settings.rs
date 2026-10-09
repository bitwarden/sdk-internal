use bitwarden_managed_settings::ManagedSettingsClient;
use bitwarden_managed_settings_types::ManagementProfile;

use crate::error::Result;

/// UniFFI wrapper for [`ManagedSettingsClient`].
///
/// The host application constructs one of these at boot, acquires a management profile from the
/// operating system's Unified Endpoint Management channel, and pushes it in with
/// [`update_from_json`](ManagedSettingsBindingClient::update_from_json).
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
    pub async fn update_profile(&self, profile: Option<ManagementProfile>) {
        self.0.update_profile(profile).await;
    }

    /// Normalize an administrator's settings object, given as a JSON string, into a profile and
    /// apply it. `None` clears the profile. Input that is not valid JSON, or whose top level is not
    /// an object, also clears the profile, and the error says why.
    pub async fn update_from_json(&self, json: Option<String>) -> Result<()> {
        Ok(self.0.update_from_json(json).await?)
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
