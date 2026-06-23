//! [`ManagedSettingsClient`] — a cheap-clone handle over the shared profile cell.

use std::sync::{Arc, RwLock};

use bitwarden_core::{Client, ClientBuilder};
use bitwarden_managed_settings_types::ManagementProfile;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Handle to the managed-settings (IT-administrator-forced) domain.
///
/// Cheap to clone: every clone shares one `Arc<RwLock<Option<ManagementProfile>>>`,
/// so `update_profile` on any clone is visible to all of them and to every
/// `Client` the host built with this handle.
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
    /// Wrap an existing shared cell. Used by [`ManagedSettingsClientExt`].
    pub(crate) fn from_profile(profile: Arc<RwLock<Option<ManagementProfile>>>) -> Self {
        Self { profile }
    }

    /// Clone of the shared cell. Used by [`ManagedSettingsBuilderExt`].
    pub(crate) fn cell(&self) -> Arc<RwLock<Option<ManagementProfile>>> {
        self.profile.clone()
    }

    /// Snapshot of the active profile, if any. Feature crates apply overrides
    /// against this. Kept off the FFI surface to keep the binding narrow.
    pub fn current_profile(&self) -> Option<ManagementProfile> {
        self.profile.read().expect("managed-settings cell poisoned").clone()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ManagedSettingsClient {
    /// Fresh handle with no active profile. The host calls this once at boot.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self { profile: Arc::new(RwLock::new(None)) }
    }

    /// Replace the active profile. `None` clears it.
    pub fn update_profile(&self, profile: Option<ManagementProfile>) {
        *self.profile.write().expect("managed-settings cell poisoned") = profile;
    }

    /// `true` if `key` is present in the active profile (`false` if none).
    pub fn is_managed(&self, key: String) -> bool {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .is_some_and(|p| p.is_managed(&key))
    }

    /// Raw JSON-encoded value for `key`, or `None` if unmanaged.
    pub fn get(&self, key: String) -> Option<String> {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .and_then(|p| p.get(&key))
    }
}

/// Inject a managed-settings handle when constructing a `Client`.
pub trait ManagedSettingsBuilderExt {
    /// Share `client`'s profile cell with the `Client` being built.
    fn with_managed_settings(self, client: &ManagedSettingsClient) -> Self;
}

impl ManagedSettingsBuilderExt for ClientBuilder {
    fn with_managed_settings(self, client: &ManagedSettingsClient) -> Self {
        self.with_managed_profile(client.cell())
    }
}

/// Read the managed-settings handle back from a constructed `Client`.
pub trait ManagedSettingsClientExt {
    /// A handle over the same cell the host pushed in.
    fn managed_settings(&self) -> ManagedSettingsClient;
}

impl ManagedSettingsClientExt for Client {
    fn managed_settings(&self) -> ManagedSettingsClient {
        ManagedSettingsClient::from_profile(self.internal.managed_profile_handle())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::Client;

    use super::*;

    #[test]
    fn new_handle_has_no_profile() {
        let c = ManagedSettingsClient::new();
        assert!(!c.is_managed("anything".to_owned()));
        assert_eq!(c.get("anything".to_owned()), None);
        assert!(c.current_profile().is_none());
    }

    #[test]
    fn update_then_query() {
        let c = ManagedSettingsClient::new();
        let mut p = ManagementProfile::empty();
        p.settings.insert("generator.password.length".to_owned(), "20".to_owned());
        c.update_profile(Some(p));
        assert!(c.is_managed("generator.password.length".to_owned()));
        assert_eq!(c.get("generator.password.length".to_owned()).as_deref(), Some("20"));
    }

    #[test]
    fn clones_share_one_cell() {
        let a = ManagedSettingsClient::new();
        let b = a.clone();
        let mut p = ManagementProfile::empty();
        p.settings.insert("k".to_owned(), "1".to_owned());
        a.update_profile(Some(p));
        assert!(b.is_managed("k".to_owned()));
        a.update_profile(None);
        assert!(!b.is_managed("k".to_owned()));
    }

    #[test]
    fn injected_handle_is_observed_through_client_ext() {
        let handle = ManagedSettingsClient::new();
        let client = Client::builder().with_managed_settings(&handle).build();
        let mut p = ManagementProfile::empty();
        p.settings.insert("k".to_owned(), "1".to_owned());
        handle.update_profile(Some(p));
        assert!(client.managed_settings().is_managed("k".to_owned()));
    }
}
