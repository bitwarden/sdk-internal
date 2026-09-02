//! WASM surface for the dev-only debug-capability tree.
//!
//! Mirrors [`bitwarden_pm::debug`] as typed wasm-bindgen handles, so the JS/TS
//! side discovers capabilities through the generated types and console
//! autocomplete rather than a runtime crawl. Compiled only under the
//! `debug-capabilities` feature.

use bitwarden_core::{client::login_method::UserLoginMethod, key_management::KeySlotIds};
use wasm_bindgen::prelude::*;

/// Root of the debug-capability tree. Reached via `PasswordManagerClient.debug()`.
#[wasm_bindgen]
pub struct DebugClient(bitwarden_pm::debug::DebugClient);

impl DebugClient {
    pub(crate) fn new(inner: bitwarden_pm::debug::DebugClient) -> Self {
        Self(inner)
    }
}

#[wasm_bindgen]
impl DebugClient {
    /// Auth/session debug capabilities.
    pub fn auth(&self) -> AuthDebugClient {
        AuthDebugClient(self.0.auth())
    }

    /// Key-store debug capabilities.
    pub fn key_store(&self) -> KeyStoreDebugClient {
        KeyStoreDebugClient(self.0.key_store())
    }

    /// Persisted-state debug capabilities.
    pub fn state(&self) -> StateDebugClient {
        StateDebugClient(self.0.state())
    }
}

/// Auth/session debug capabilities.
#[wasm_bindgen]
pub struct AuthDebugClient(bitwarden_core::debug::AuthDebug);

#[wasm_bindgen]
impl AuthDebugClient {
    /// Read the user's stored login method, or `undefined` if none is set.
    pub async fn login_method(&self) -> Option<UserLoginMethod> {
        self.0.login_method().await
    }

    /// Overwrite the user's stored login method. Debug-only.
    pub async fn set_login_method(&self, method: UserLoginMethod) {
        self.0.set_login_method(method).await;
    }
}

/// Key-store debug capabilities.
#[wasm_bindgen]
pub struct KeyStoreDebugClient(bitwarden_crypto::KeyStoreDebug<KeySlotIds>);

#[wasm_bindgen]
impl KeyStoreDebugClient {
    /// List the loaded key slots per backend. Key material is redacted unless
    /// the crypto crate was built with `dangerous-crypto-debug`.
    pub fn list(&self) -> bitwarden_crypto::KeyStoreSummary {
        self.0.summary()
    }
}

/// Persisted-state debug capabilities.
#[wasm_bindgen]
pub struct StateDebugClient(bitwarden_core::debug::StateDebug);

#[wasm_bindgen]
impl StateDebugClient {
    /// Names of every registered repository (client- and SDK-managed).
    pub fn types(&self) -> Vec<String> {
        self.0.types()
    }

    /// List a repository's values as a JSON-array string (`JSON.parse` it),
    /// addressed by type name. Values only (no keys). Raw stored JSON.
    pub async fn list(&self, type_name: String) -> String {
        self.0.list(type_name).await.to_string()
    }

    /// Read one item by type name and string key, as a JSON string (`"null"` if
    /// absent).
    pub async fn get(&self, type_name: String, key: String) -> String {
        self.0.get(type_name, key).await.to_string()
    }

    /// Write one item by type name and string key. `value` is the item as a JSON
    /// string. Debug-only; bypasses the public API.
    pub async fn set(&self, type_name: String, key: String, value: String) {
        self.0.set(type_name, key, value).await;
    }
}
