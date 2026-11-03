use std::collections::HashMap;

use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur while reading a [`ManagementProfile`].
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct ManagementProfile {
    /// Schema version. Bumped when the dotted-key namespace changes incompatibly.
    pub version: u32,
    /// Unix timestamp (seconds) at which the host last refreshed the profile.
    ///
    /// This field participates in equality, so two profiles carrying identical `settings` compare
    /// unequal when the host re-read the source and re-stamped the timestamp. Do not use `==` to
    /// detect whether the managed settings themselves changed; compare `settings` instead.
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
        ManagementProfile {
            version: 1,
            updated_at: 1_750_000_000,
            settings: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn is_managed_reflects_key_presence() {
        let profile = profile_with(&[("environment.base", "\"https://vault.example.com\"")]);

        assert!(profile.is_managed("environment.base"));
        assert!(!profile.is_managed("environment.api"));
    }

    #[test]
    fn get_returns_the_raw_json_encoded_value() {
        let profile = profile_with(&[("environment.base", "\"https://vault.example.com\"")]);

        assert_eq!(
            profile.get("environment.base"),
            Some("\"https://vault.example.com\"".to_string())
        );
    }

    #[test]
    fn get_returns_none_for_an_absent_key() {
        let profile = profile_with(&[("environment.base", "\"https://vault.example.com\"")]);

        assert_eq!(profile.get("environment.api"), None);
    }

    #[test]
    fn get_as_decodes_a_present_value() {
        let profile = profile_with(&[("generator.password.length", "14")]);

        assert_eq!(
            profile.get_as::<u32>("generator.password.length").unwrap(),
            Some(14)
        );
    }

    #[test]
    fn get_as_returns_none_for_an_absent_key() {
        let profile = profile_with(&[("generator.password.length", "14")]);

        assert_eq!(
            profile
                .get_as::<u32>("generator.password.uppercase")
                .unwrap(),
            None
        );
    }

    #[test]
    fn get_as_errors_when_the_value_does_not_match_the_requested_type() {
        let profile = profile_with(&[("generator.password.length", "\"fourteen\"")]);

        let error = profile
            .get_as::<u32>("generator.password.length")
            .expect_err("decoding a string as u32 should fail");

        assert!(matches!(error, ManagedSettingsError::Decode(_)));
    }

    #[test]
    fn empty_profile_manages_nothing() {
        let profile = ManagementProfile::empty();

        assert!(!profile.is_managed("environment.base"));
        assert_eq!(profile.get("environment.base"), None);
        assert_eq!(profile.get_as::<u32>("environment.base").unwrap(), None);
    }
}
