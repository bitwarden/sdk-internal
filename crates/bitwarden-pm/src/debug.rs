//! Dev-only debug-capability tree, rooted on [`PasswordManagerClient`].
//!
//! Mirrors the public client tree, but each node exposes only debug
//! capabilities. A node hands back a handle authored in the crate that owns the
//! state it reaches into, so that crate's internals stay reachable. Compiled
//! only under the `debug-capabilities` feature.

use bitwarden_core::Client;
use bitwarden_state::debug::StateRegistryDebugExt as _;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::PasswordManagerClient;

/// Root of the debug-capability tree. Routes to per-crate capability handles.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct DebugClient {
    client: Client,
}

impl PasswordManagerClient {
    /// Entry point for dev-only debug capabilities (bypass the public API).
    pub fn debug(&self) -> DebugClient {
        // The wasm and mobile bindings build a memory-backed registry that never
        // runs the SDK-managed migrations, so their debug index would otherwise
        // omit SDK-managed types (e.g. `Setting`). Registering here (idempotent)
        // makes the browse cover them wherever the tree is reachable.
        self.0
            .internal
            .state_registry()
            .debug_register_migrations(&crate::migrations::get_sdk_managed_migrations());
        DebugClient {
            client: self.0.clone(),
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl DebugClient {
    /// Persisted-state debug capabilities (browse the SDK's state registry).
    /// Authored in `bitwarden-state`, where the registry lives.
    pub fn state(&self) -> bitwarden_state::debug::StateDebug {
        self.client.internal.state_registry().debug()
    }
}
