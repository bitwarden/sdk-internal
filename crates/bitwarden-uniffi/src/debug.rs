//! UniFFI surface for the dev-only debug-capability tree.
//!
//! Wraps the debug tree composed in `bitwarden-pm` as uniffi objects, the same
//! way the other binding clients here wrap their pm sub-clients. Compiled only
//! under the `debug-capabilities` feature.

/// UniFFI wrapper for the debug-tree root.
#[derive(uniffi::Object)]
pub struct DebugClient(pub(crate) bitwarden_pm::debug::DebugClient);

#[uniffi::export]
impl DebugClient {
    /// Persisted-state debug capabilities.
    pub fn state(&self) -> StateDebug {
        StateDebug(self.0.state())
    }
}

/// UniFFI wrapper for the state-registry debug handle.
#[derive(uniffi::Object)]
pub struct StateDebug(pub(crate) bitwarden_state::debug::StateDebug);

#[uniffi::export(async_runtime = "tokio")]
impl StateDebug {
    /// Names of every registered repository (client- and SDK-managed).
    pub fn types(&self) -> Vec<String> {
        self.0.types()
    }

    /// List a repository's values as a JSON-array string, addressed by type name.
    /// Values only (no keys).
    pub async fn list(&self, type_name: String) -> String {
        self.0.list(type_name).await
    }

    /// Read one item by type name and string key, as a JSON string (`"null"` if
    /// absent).
    pub async fn get(&self, type_name: String, key: String) -> String {
        self.0.get(type_name, key).await
    }

    /// Write one item by type name and string key. Returns `true` if the write
    /// landed, so a caller can tell a no-op from a write.
    pub async fn set(&self, type_name: String, key: String, value: String) -> bool {
        self.0.set(type_name, key, value).await
    }
}
