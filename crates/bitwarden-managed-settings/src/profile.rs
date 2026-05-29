//! Data types describing an active managed-settings profile.
//!
//! A [`ManagementProfile`] is a snapshot of the configuration an IT administrator
//! has forced on this client, as delivered through an OS-mediated channel.
//! See the crate `DESIGN.md` for the trust model.

use std::collections::HashMap;

use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Errors that can occur while operating on a [`ManagementProfile`].
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ManagedSettingsError {
    /// The value stored under the requested key could not be parsed as JSON of the
    /// expected shape.
    #[error("Failed to decode managed settings value: {0}")]
    Decode(String),
}

/// Channel through which a [`ManagementProfile`] was acquired.
///
/// This is **diagnostics only**. The SDK never branches on source: presence of
/// a key in the profile means the key is forced, regardless of which OS
/// channel delivered it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum ManagementSource {
    /// Apple managed app configuration (`NSUserDefaults` / `com.apple.configuration.managed`).
    MdmApple,
    /// Android `RestrictionsManager`.
    MdmAndroid,
    /// Windows Group Policy under `HKLM\SOFTWARE\Policies\Bitwarden`.
    PolicyWindows,
    /// Linux policy files under `/etc/bitwarden/policies`.
    PolicyLinux,
    /// Chromium-family `chrome.storage.managed` for the browser extension.
    ExtensionManagedStorage,
}

/// A point-in-time snapshot of administrator-forced configuration for this client.
///
/// `settings` maps dotted keys (e.g. `"generator.password.length"`) to **JSON-encoded
/// strings**, not arbitrary `serde_json::Value`s. This is deliberate: `serde_json::Value`
/// has no UniFFI representation, but a plain `String` does. Callers parse on demand
/// through [`get`](ManagementProfile::get).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ManagementProfile {
    /// Schema version of this profile. Bumped when the dotted-key namespace
    /// changes incompatibly.
    pub version: u32,
    /// Channel through which the profile was acquired. Diagnostics only.
    pub source: ManagementSource,
    /// Unix timestamp (seconds) at which the host last refreshed the profile.
    pub fetched_at: i64,
    /// Dotted key → JSON-encoded value string.
    pub settings: HashMap<String, String>,
}

impl ManagementProfile {
    /// Returns an empty profile from the given source.
    ///
    /// Empty profiles are equivalent to "no admin overrides" — any [`is_managed`]
    /// call will return `false`.
    pub fn empty(source: ManagementSource) -> Self {
        Self {
            version: 1,
            source,
            fetched_at: 0,
            settings: HashMap::new(),
        }
    }

    /// Returns `true` if `key` is present in this profile.
    ///
    /// Per the trust model, presence implies the value is forced. There is no
    /// `locked` flag and no `recommended` tier.
    pub fn is_managed(&self, key: &str) -> bool {
        self.settings.contains_key(key)
    }

    /// Returns the raw JSON-encoded string stored under `key`, if any.
    ///
    /// The returned string is the **already-JSON-encoded** value; callers
    /// typically parse it with [`serde_json::from_str`].
    pub fn get(&self, key: &str) -> Option<String> {
        self.settings.get(key).cloned()
    }

    /// Helper: get and JSON-decode a value to `T`.
    pub fn get_as<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ManagedSettingsError> {
        match self.settings.get(key) {
            None => Ok(None),
            Some(raw) => serde_json::from_str(raw)
                .map(Some)
                .map_err(|e| ManagedSettingsError::Decode(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_reports_no_managed_keys() {
        let p = ManagementProfile::empty(ManagementSource::PolicyLinux);
        assert!(!p.is_managed("any.key"));
        assert_eq!(p.get("any.key"), None);
    }

    #[test]
    fn is_managed_returns_true_for_known_key() {
        let mut p = ManagementProfile::empty(ManagementSource::MdmApple);
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        assert!(p.is_managed("generator.password.length"));
        assert_eq!(p.get("generator.password.length").as_deref(), Some("20"));
    }

    #[test]
    fn get_as_parses_typed_values() {
        let mut p = ManagementProfile::empty(ManagementSource::ExtensionManagedStorage);
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        p.settings
            .insert("generator.password.uppercase".to_owned(), "true".to_owned());

        let length: Option<u8> = p.get_as("generator.password.length").unwrap();
        assert_eq!(length, Some(20));

        let upper: Option<bool> = p.get_as("generator.password.uppercase").unwrap();
        assert_eq!(upper, Some(true));

        let missing: Option<u8> = p.get_as("generator.password.missing").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn get_as_reports_decode_errors() {
        let mut p = ManagementProfile::empty(ManagementSource::PolicyWindows);
        p.settings
            .insert("k".to_owned(), "not-a-number".to_owned());
        let err = p.get_as::<u8>("k").unwrap_err();
        let ManagedSettingsError::Decode(msg) = err;
        assert!(!msg.is_empty());
    }

    #[test]
    fn profile_round_trips_through_json() {
        let mut p = ManagementProfile::empty(ManagementSource::PolicyWindows);
        p.settings.insert("a.b".to_owned(), "1".to_owned());
        let json = serde_json::to_string(&p).unwrap();
        let p2: ManagementProfile = serde_json::from_str(&json).unwrap();
        assert!(p2.is_managed("a.b"));
        assert_eq!(p2.source, ManagementSource::PolicyWindows);
    }
}
