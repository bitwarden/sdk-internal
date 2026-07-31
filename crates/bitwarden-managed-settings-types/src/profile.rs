use std::collections::HashMap;

use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

/// Errors that can occur while reading a [`ManagementProfile`].
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ManagedSettingsError {
    /// The value stored under the requested key could not be parsed as the expected shape.
    #[error("Failed to decode managed settings value: {0}")]
    Decode(String),
}

/// A point-in-time snapshot of administrator-forced configuration for this client.
///
/// `settings` maps dotted keys (e.g. `"generator.password.length"`) to JSON-encoded
/// strings. A plain `String` is used (not `serde_json::Value`) because it has a UniFFI
/// representation. Callers parse on demand through [`get_as`](ManagementProfile::get_as).
///
/// This is client configuration forced by an operating system's Unified Endpoint Management
/// (UEM/MDM) channel. It is not Vault Data and involves no cryptography.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ManagementProfile {
    /// Schema version. Bumped when the dotted-key namespace changes incompatibly.
    pub version: u32,
    /// Unix timestamp (seconds) at which the host last refreshed the profile.
    pub updated_at: i64,
    /// Dotted key to JSON-encoded value string.
    pub settings: HashMap<String, String>,
}

impl ManagementProfile {
    /// An empty profile, equivalent to "no admin overrides". Every `is_managed` returns `false`.
    pub fn empty() -> Self {
        Self {
            version: 1,
            updated_at: 0,
            settings: HashMap::new(),
        }
    }

    /// Returns `true` if `key` is present. Presence implies the value is forced.
    pub fn is_managed(&self, key: &str) -> bool {
        self.settings.contains_key(key)
    }

    /// Returns the raw JSON-encoded string stored under `key`, if any.
    pub fn get(&self, key: &str) -> Option<String> {
        self.settings.get(key).cloned()
    }

    /// Get and JSON-decode a value to `T`.
    ///
    /// Returns `Ok(None)` when `key` is absent, `Ok(Some(T))` on a successful decode, and
    /// [`ManagedSettingsError::Decode`] when the stored value cannot be parsed as `T`.
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

    fn profile_with(entries: &[(&str, &str)]) -> ManagementProfile {
        let mut profile = ManagementProfile::empty();
        for (key, value) in entries {
            profile
                .settings
                .insert((*key).to_string(), (*value).to_string());
        }
        profile
    }

    #[test]
    fn is_managed_reflects_presence() {
        let profile = profile_with(&[("environment.base", "\"https://vault.example.com\"")]);
        assert!(profile.is_managed("environment.base"));
        assert!(!profile.is_managed("environment.api"));
    }

    #[test]
    fn get_returns_raw_json_for_present_key() {
        let profile = profile_with(&[("generator.password.length", "42")]);
        assert_eq!(
            profile.get("generator.password.length"),
            Some("42".to_string())
        );
    }

    #[test]
    fn get_returns_none_for_absent_key() {
        let profile = profile_with(&[("generator.password.length", "42")]);
        assert_eq!(profile.get("missing.key"), None);
    }

    #[test]
    fn get_as_decodes_present_value() {
        let profile = profile_with(&[("generator.password.length", "42")]);
        let value: Option<u32> = profile
            .get_as("generator.password.length")
            .expect("value should decode");
        assert_eq!(value, Some(42));
    }

    #[test]
    fn get_as_returns_none_for_absent_key() {
        let profile = profile_with(&[("generator.password.length", "42")]);
        let value: Option<u32> = profile
            .get_as("missing.key")
            .expect("absent key is Ok(None)");
        assert_eq!(value, None);
    }

    #[test]
    fn get_as_returns_decode_error_on_bad_parse() {
        let profile = profile_with(&[("generator.password.length", "\"not-a-number\"")]);
        let result: Result<Option<u32>, _> = profile.get_as("generator.password.length");
        assert!(matches!(result, Err(ManagedSettingsError::Decode(_))));
    }

    #[test]
    fn empty_profile_returns_none_for_any_get() {
        let profile = ManagementProfile::empty();
        assert_eq!(profile.get("anything"), None);
        assert!(!profile.is_managed("anything"));
    }
}
