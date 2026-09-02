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
