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
    /// Auth/session debug capabilities (login method, …). Authored in
    /// `bitwarden-core`, where the state lives.
    pub fn auth(&self) -> bitwarden_core::debug::AuthDebug {
        bitwarden_core::debug::AuthDebug::new(self.client.clone())
    }

    /// Key-store debug capabilities (slot listing). Authored in
    /// `bitwarden-crypto`, where the store internals live.
    pub fn key_store(
        &self,
    ) -> bitwarden_crypto::KeyStoreDebug<bitwarden_core::key_management::KeySlotIds> {
        bitwarden_crypto::KeyStoreDebug::new(self.client.internal.get_key_store().clone())
    }

    /// Persisted-state debug capabilities (browse the SDK's setting registry).
    /// Authored in `bitwarden-core`, where the state registry lives.
    pub fn state(&self) -> bitwarden_core::debug::StateDebug {
        bitwarden_core::debug::StateDebug::new(self.client.clone())
    }
}
