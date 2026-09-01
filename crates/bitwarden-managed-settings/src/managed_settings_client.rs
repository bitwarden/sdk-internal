use std::sync::{Arc, RwLock};

use bitwarden_managed_settings_types::ManagementProfile;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Handle to the host system's Unified Endpoint Management profile.
///
/// The host application constructs one of these at boot and pushes profiles into it. Clones share
/// the underlying profile, so an update pushed through one clone is observed by all of them.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ManagedSettingsClient {
    profile: Arc<RwLock<Option<ManagementProfile>>>,
}

impl Default for ManagedSettingsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Methods whose signatures cannot cross an FFI boundary, so they stay off the binding surface.
impl ManagedSettingsClient {
    /// The shared profile cell, so a constructed SDK client can read the same profile the host
    /// pushes into this handle.
    pub fn cell(&self) -> Arc<RwLock<Option<ManagementProfile>>> {
        self.profile.clone()
    }

    /// The active profile, or `None` when the host has not pushed one.
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
        match &profile {
            Some(p) => tracing::info!(
                version = p.version,
                keys = p.settings.len(),
                "Managed settings profile updated"
            ),
            None => tracing::info!("Managed settings profile cleared"),
        }

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn profile_with(key: &str, json_value: &str) -> ManagementProfile {
        ManagementProfile {
            version: 1,
            updated_at: 1_750_000_000,
            settings: HashMap::from([(key.to_string(), json_value.to_string())]),
        }
    }

    #[test]
    fn a_new_client_manages_nothing() {
        let client = ManagedSettingsClient::new();

        assert_eq!(client.get("environment.base".to_string()), None);
        assert!(!client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), None);
    }

    #[test]
    fn get_reflects_an_updated_profile() {
        let client = ManagedSettingsClient::new();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone()));

        assert_eq!(
            client.get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
        assert!(client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), Some(profile));
    }

    #[test]
    fn updating_with_none_clears_the_profile() {
        let client = ManagedSettingsClient::new();
        client.update_profile(Some(profile_with("environment.base", "\"https://a\"")));

        client.update_profile(None);

        assert_eq!(client.get("environment.base".to_string()), None);
        assert!(!client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), None);
    }

    #[test]
    fn a_clone_observes_an_update_made_on_the_original() {
        let client = ManagedSettingsClient::new();
        let clone = client.clone();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone()));

        assert_eq!(
            clone.get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
        assert_eq!(clone.current_profile(), Some(profile));
    }

    #[test]
    fn the_shared_cell_observes_an_update_made_through_the_handle() {
        let client = ManagedSettingsClient::new();
        let cell = client.cell();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone()));

        assert_eq!(
            *cell.read().expect("managed-settings cell poisoned"),
            Some(profile)
        );
    }
}
