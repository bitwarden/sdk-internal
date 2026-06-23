//! Data types describing an active managed-settings profile.

use std::collections::HashMap;

use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

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
        let p = ManagementProfile::empty();
        assert!(!p.is_managed("any.key"));
        assert_eq!(p.get("any.key"), None);
    }

    #[test]
    fn is_managed_and_get_for_known_key() {
        let mut p = ManagementProfile::empty();
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        assert!(p.is_managed("generator.password.length"));
        assert_eq!(p.get("generator.password.length").as_deref(), Some("20"));
    }

    #[test]
    fn get_as_parses_typed_values() {
        let mut p = ManagementProfile::empty();
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        let length: Option<u8> = p.get_as("generator.password.length").unwrap();
        assert_eq!(length, Some(20));
        let missing: Option<u8> = p.get_as("absent").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn get_as_reports_decode_errors() {
        let mut p = ManagementProfile::empty();
        p.settings.insert("k".to_owned(), "not-a-number".to_owned());
        let err = p.get_as::<u8>("k").unwrap_err();
        let ManagedSettingsError::Decode(msg) = err;
        assert!(!msg.is_empty());
    }

    #[test]
    fn profile_round_trips_through_json() {
        let mut p = ManagementProfile::empty();
        p.settings.insert("a.b".to_owned(), "1".to_owned());
        let json = serde_json::to_string(&p).unwrap();
        let p2: ManagementProfile = serde_json::from_str(&json).unwrap();
        assert!(p2.is_managed("a.b"));
        assert_eq!(p2.version, 1);
    }
}
