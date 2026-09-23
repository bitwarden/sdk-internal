//! Dev-only debug-capability tree, rooted on [`PasswordManagerClient`].
//!
//! A parallel tree to the public client tree: it mirrors the client hierarchy
//! but exposes only debug capabilities, and it authors nothing itself. Each node
//! hands back a capability handle that lives in the crate owning the underlying
//! state (so that crate's internals are reachable), the same way the real
//! [`PasswordManagerClient`] hands back sub-clients it did not author. Compiled
//! only under the `debug-capabilities` feature.

use bitwarden_core::Client;

use crate::PasswordManagerClient;

/// Root of the debug-capability tree. Routes to per-crate capability handles.
pub struct DebugClient {
    client: Client,
}

impl PasswordManagerClient {
    /// Entry point for dev-only debug capabilities (bypass the public API).
    pub fn debug(&self) -> DebugClient {
        DebugClient {
            client: self.0.clone(),
        }
    }
}

impl DebugClient {
    /// Persisted-state debug capabilities (browse the SDK's state registry).
    /// Authored in `bitwarden-core`, where the state registry lives.
    pub fn state(&self) -> bitwarden_core::debug::StateDebug {
        bitwarden_core::debug::StateDebug::new(self.client.clone())
    }
}
