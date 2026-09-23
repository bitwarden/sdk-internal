//! Dev-only debug capabilities.
//!
//! These reach past the public API into internal client state so automated
//! tooling can read and drive things the normal API does not expose. They are
//! compiled only under the `debug-capabilities` feature and must never ship in
//! production. Kept in their own module, deliberately separate from the regular
//! client API.

use serde_json::Value;

use crate::Client;

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
