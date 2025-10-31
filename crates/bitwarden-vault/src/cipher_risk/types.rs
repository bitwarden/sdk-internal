use std::collections::HashMap;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::CipherId;

/// Result of checking password exposure via HIBP API.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "type", content = "value")]
pub enum ExposedPasswordResult {
    /// Password exposure check was not performed (check_exposed was false or password was empty)
    NotChecked,
    /// Successfully checked, found in this many breaches
    Found(u32),
    /// HIBP API request failed with error message
    Error(String),
}

/// Login cipher data needed for risk evaluation.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherLoginDetails {
    /// Cipher ID to identify which cipher in results.
    pub id: CipherId,
    /// The decrypted password to evaluate.
    pub password: String,
    /// Username or email (login ciphers only have one field).
    pub username: Option<String>,
}

/// Password reuse map wrapper for WASM compatibility.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(transparent)]
pub struct PasswordReuseMap {
    /// Map of passwords to their occurrence count.
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, number>"))]
    pub map: HashMap<String, u32>,
}

impl PasswordReuseMap {
    /// Create a new PasswordReuseMap from a list of passwords.
    pub fn new(passwords: Vec<CipherLoginDetails>) -> Self {
        let mut map = HashMap::new();
        for details in passwords {
            if !details.password.is_empty() {
                *map.entry(details.password).or_insert(0) += 1;
            }
        }
        Self { map }
    }
}

/// Options for configuring risk computation.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct CipherRiskOptions {
    /// Pre-computed password reuse map (password → count).
    /// If provided, enables reuse detection across ciphers.
    #[serde(default)]
    pub password_map: Option<PasswordReuseMap>,
    /// Whether to check passwords against Have I Been Pwned API.
    /// When true, makes network requests to check for exposed passwords.
    #[serde(default)]
    pub check_exposed: bool,
    /// Optional HIBP API base URL override. When None, uses the production HIBP URL.
    /// Can be used for testing or alternative password breach checking services.
    #[serde(default)]
    pub hibp_base_url: Option<String>,
}

/// Risk evaluation result for a single cipher.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherRiskResult {
    /// Cipher ID matching the input CipherLoginDetails.
    pub id: CipherId,
    /// Password strength score from 0 (weakest) to 4 (strongest).
    /// Calculated using zxcvbn with cipher-specific context.
    pub password_strength: u8,
    /// Result of checking password exposure via HIBP API.
    /// - `NotChecked`: check_exposed was false, or password was empty
    /// - `Found(n)`: Successfully checked, found in n breaches
    /// - `Error(msg)`: HIBP API request failed for this cipher with the given error message
    pub exposed_result: ExposedPasswordResult,
    /// Number of times this password appears in the provided password_map.
    /// None if not found or if no password_map was provided.
    pub reuse_count: Option<u32>,
}
