use std::sync::{Arc, RwLock};

use bitwarden_core::Client;
use bitwarden_managed_settings_types::ManagementProfile;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Handle to the host system's Unified Endpoint Management profile.
///
/// The host application should provide an instance of this type when instantiating a
/// `bitwarden-core` [`Client`]. The handle is cloneable and every clone shares the same underlying
/// profile cell, so an `update_profile` on any clone is observed by all of them and by the SDK.
///
/// Managed settings are client configuration forced by an operating system's UEM/MDM channel. They
/// are not Vault Data and involve no cryptography.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct ManagedSettingsClient {
    profile: Arc<RwLock<Option<ManagementProfile>>>,
}

impl Default for ManagedSettingsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagedSettingsClient {
    /// Wraps an existing shared profile cell. Used by [`ManagedSettingsClientExt`] to read the
    /// cell back off a constructed [`Client`].
    pub(crate) fn from_profile(profile: Arc<RwLock<Option<ManagementProfile>>>) -> Self {
        Self { profile }
    }

    /// Returns a clone of the shared profile cell for injection into a `bitwarden-core`
    /// [`crate::ManagedSettingsClientExt`] `ClientBuilder`.
    pub fn cell(&self) -> Arc<RwLock<Option<ManagementProfile>>> {
        self.profile.clone()
    }

    /// Returns a clone of the active profile, or `None` when no profile has been pushed.
    pub fn current_profile(&self) -> Option<ManagementProfile> {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .clone()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ManagedSettingsClient {
    /// Fresh handle with no active profile. The host should call this once at boot.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            profile: Arc::new(RwLock::new(None)),
        }
    }

    /// Replace the active profile. Clear the profile with `None`.
    pub fn update_profile(&self, profile: Option<ManagementProfile>) {
        *self
            .profile
            .write()
            .expect("managed-settings cell poisoned") = profile;
    }

    /// Returns `true` if `key` is present in the active profile.
    pub fn is_managed(&self, key: String) -> bool {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .is_some_and(|p| p.is_managed(&key))
    }

    /// Raw JSON-encoded value for `key`, if a value is present.
    pub fn get(&self, key: String) -> Option<String> {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .and_then(|p| p.get(&key))
    }
}

/// Reads the UEM profile handle back from a constructed `bitwarden-core` [`Client`].
pub trait ManagedSettingsClientExt {
    /// Returns a [`ManagedSettingsClient`] sharing the client's managed-settings profile cell.
    fn managed_settings(&self) -> ManagedSettingsClient;
}

impl ManagedSettingsClientExt for Client {
    fn managed_settings(&self) -> ManagedSettingsClient {
        ManagedSettingsClient::from_profile(self.internal.managed_profile_handle())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::ClientBuilder;

    use super::*;

    fn profile_with(key: &str, value: &str) -> ManagementProfile {
        let mut profile = ManagementProfile::empty();
        profile.settings.insert(key.to_string(), value.to_string());
        profile
    }

    #[test]
    fn new_client_returns_none_for_any_key() {
        let client = ManagedSettingsClient::new();
        assert_eq!(client.get("environment.base".to_string()), None);
        assert!(!client.is_managed("environment.base".to_string()));
    }

    #[test]
    fn clone_observes_update_to_original() {
        let original = ManagedSettingsClient::new();
        let clone = original.clone();

        original.update_profile(Some(profile_with("environment.base", "\"https://vault\"")));

        assert_eq!(
            clone.get("environment.base".to_string()),
            Some("\"https://vault\"".to_string())
        );
        assert!(clone.is_managed("environment.base".to_string()));
    }

    #[test]
    fn get_reflects_update_profile() {
        let client = ManagedSettingsClient::new();
        assert_eq!(client.get("environment.base".to_string()), None);

        client.update_profile(Some(profile_with("environment.base", "\"https://vault\"")));
        assert_eq!(
            client.get("environment.base".to_string()),
            Some("\"https://vault\"".to_string())
        );

        client.update_profile(None);
        assert_eq!(client.get("environment.base".to_string()), None);
    }

    #[test]
    fn client_ext_reads_back_injected_cell() {
        let handle = ManagedSettingsClient::new();
        handle.update_profile(Some(profile_with("environment.base", "\"https://vault\"")));

        let client = ClientBuilder::new()
            .with_managed_profile(handle.cell())
            .build();

        assert_eq!(
            client
                .managed_settings()
                .get("environment.base".to_string()),
            Some("\"https://vault\"".to_string())
        );
    }
}
