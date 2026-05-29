//! [`ManagedSettingsClient`] — the sub-client returned by
//! [`ManagedSettingsClientExt::managed_settings`] on a [`bitwarden_core::Client`].

use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{profile::ManagementProfile, store};

/// Client for the managed-settings (IT admin centrally-forced settings) domain.
///
/// Stateless handle: instances are cheap and the active profile lives in the
/// crate-level store (prototype) or, in production, in the host-implemented
/// `ManagementProfileProvider` injected at PM builder time.
///
/// Obtained via [`ManagedSettingsClientExt::managed_settings`] on a [`Client`].
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ManagedSettingsClient {
    _private: (),
}

impl Default for ManagedSettingsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagedSettingsClient {
    /// Creates a new handle.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Returns a clone of the active profile, if any.
    ///
    /// Internal-only: feature crates that want to consult the profile use this.
    /// We expose `is_managed` / `get` over FFI instead of the whole profile to
    /// keep the FFI surface narrow.
    pub fn current_profile(&self) -> Option<ManagementProfile> {
        store::current_profile()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ManagedSettingsClient {
    /// Replaces the active managed-settings profile.
    ///
    /// `None` (passed as `null`/`undefined` on the FFI boundary) clears the
    /// profile, restoring "no admin overrides" behavior.
    ///
    /// **Prototype API.** The production design is a host-implemented pull
    /// provider (`ManagementProfileProvider`) injected via the PM builder.
    /// See `DESIGN.md`.
    pub fn update_profile(&self, profile: Option<ManagementProfile>) {
        store::set_profile(profile);
    }

    /// Returns `true` if `key` is present in the active profile.
    ///
    /// Returns `false` when there is no active profile.
    pub fn is_managed(&self, key: String) -> bool {
        store::current_profile()
            .as_ref()
            .is_some_and(|p| p.is_managed(&key))
    }

    /// Returns the raw JSON-encoded string stored under `key`, if any.
    pub fn get(&self, key: String) -> Option<String> {
        store::current_profile().and_then(|p| p.get(&key))
    }
}

/// Extension trait that adds a [`managed_settings`](ManagedSettingsClientExt::managed_settings)
/// method to [`Client`].
pub trait ManagedSettingsClientExt {
    /// Returns a new [`ManagedSettingsClient`] handle.
    fn managed_settings(&self) -> ManagedSettingsClient;
}

impl ManagedSettingsClientExt for Client {
    fn managed_settings(&self) -> ManagedSettingsClient {
        ManagedSettingsClient::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{
        profile::{ManagementProfile, ManagementSource},
        store,
    };

    // The store is process-global, so tests in this module take a mutex to
    // avoid stomping on each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        store::reset_for_test();
        g
    }

    #[test]
    fn no_profile_is_managed_returns_false() {
        let _g = lock();
        let c = ManagedSettingsClient::new();
        assert!(!c.is_managed("anything".to_owned()));
        assert_eq!(c.get("anything".to_owned()), None);
    }

    #[test]
    fn update_profile_then_query() {
        let _g = lock();
        let c = ManagedSettingsClient::new();
        let mut p = ManagementProfile::empty(ManagementSource::PolicyWindows);
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        c.update_profile(Some(p));

        assert!(c.is_managed("generator.password.length".to_owned()));
        assert_eq!(
            c.get("generator.password.length".to_owned()).as_deref(),
            Some("20")
        );
        assert!(!c.is_managed("generator.password.special".to_owned()));
    }

    #[test]
    fn update_profile_with_none_clears() {
        let _g = lock();
        let c = ManagedSettingsClient::new();
        let mut p = ManagementProfile::empty(ManagementSource::MdmApple);
        p.settings.insert("a".to_owned(), "1".to_owned());
        c.update_profile(Some(p));
        assert!(c.is_managed("a".to_owned()));

        c.update_profile(None);
        assert!(!c.is_managed("a".to_owned()));
    }

    #[test]
    fn client_ext_returns_handle() {
        let _g = lock();
        let client = Client::new(None);
        let _ms = client.managed_settings();
    }
}
