//! Dev-only debug capabilities.
//!
//! These reach past the public API into internal client state so automated
//! tooling can read and drive things the normal API does not expose. They are
//! compiled only under the `debug-capabilities` feature and must never ship in
//! production. Kept in their own module, deliberately separate from the regular
//! client API.

use serde_json::Value;

use crate::{
    Client,
    client::login_method::{LoginMethod, UserLoginMethod},
};

/// Debug capabilities over a user's auth/session state.
///
/// Holds a cheap, `Arc`-backed [`Client`] clone, so it owns everything it needs
/// and nothing borrows across an FFI boundary.
pub struct AuthDebug {
    client: Client,
}

impl AuthDebug {
    /// Wrap the owning client. Built by the debug-tree root, not called directly.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Read the user's stored login method (client id, email, KDF, and — for
    /// API-key logins — the client secret). `None` on a locked or
    /// service-account client. Bypasses the public API.
    pub async fn login_method(&self) -> Option<UserLoginMethod> {
        self.client.internal.get_login_method().await
    }

    /// Overwrite the user's stored login method. Debug-only: bypasses the normal
    /// login flow to drive a client into a specific state.
    pub async fn set_login_method(&self, method: UserLoginMethod) {
        self.client
            .internal
            .set_login_method(LoginMethod::User(method))
            .await;
    }
}

/// Debug access to the SDK's state registry — a generic browse over every
/// registered repository, both client-managed and SDK-managed.
///
/// Holds a cheap, `Arc`-backed [`Client`] clone.
pub struct StateDebug {
    client: Client,
}

impl StateDebug {
    /// Wrap the owning client. Built by the debug-tree root.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Names of every registered repository (client- and SDK-managed).
    pub fn types(&self) -> Vec<String> {
        self.client.internal.state_registry.debug_types()
    }

    /// List a repository's values as JSON, addressed by type name. Values only —
    /// the repository API lists values without their keys. Returns raw stored
    /// JSON (no redaction); dev-only, bypasses the public API.
    pub async fn list(&self, type_name: String) -> Value {
        Value::Array(
            self.client
                .internal
                .state_registry
                .debug_list(&type_name)
                .await,
        )
    }

    /// Read one item by type name and string key, or `null` if absent.
    pub async fn get(&self, type_name: String, key: String) -> Value {
        self.client
            .internal
            .state_registry
            .debug_get(&type_name, &key)
            .await
            .unwrap_or(Value::Null)
    }

    /// Write one item by type name and string key. `value_json` is the item as a
    /// JSON string. No-ops on an unknown type, bad key, or non-deserializable value.
    pub async fn set(&self, type_name: String, key: String, value_json: String) {
        let Ok(value) = serde_json::from_str::<Value>(&value_json) else {
            return;
        };
        self.client
            .internal
            .state_registry
            .debug_set(&type_name, &key, value)
            .await;
    }
}
