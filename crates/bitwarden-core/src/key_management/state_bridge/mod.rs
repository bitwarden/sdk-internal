//! The state bridge is a temporary layer that allows quickly transitioning
//! non-repository shaped state to be accessible from within the SDK.
//!
//! This is not a public API that shoudl be used by other teams. It will be
//! replaced by a `bitwarden-state` implementation as soon as that gains support
//! for non-repository state.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitwarden_crypto::{EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};

mod client;
pub use client::StateBridgeClient;
#[cfg(feature = "wasm")]
mod wasm;

/// Host-provided storage bridge for key-management state.
///
/// SDK consumers register an implementation that persists or caches sensitive
/// account state across unlock flows.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StateBridgeImpl: Send + Sync {
    /// Stores the current decrypted user key.
    async fn set_user_key(&self, user_key: SymmetricCryptoKey);
    /// Returns the current decrypted user key, if available.
    async fn get_user_key(&self) -> Option<SymmetricCryptoKey>;
    /// Removes any stored decrypted user key.
    async fn clear_user_key(&self);

    /// Stores the PIN envelope that can survive process restarts.
    async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope);
    /// Returns the persistent PIN envelope, if one is stored.
    async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    /// Clears the persistent PIN envelope.
    async fn clear_persistent_pin_envelope(&self);

    /// Stores the in-memory PIN envelope for the current session.
    async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope);
    /// Returns the in-memory PIN envelope, if one is currently available.
    async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    /// Clears the in-memory PIN envelope.
    async fn clear_ephemeral_pin_envelope(&self);

    /// Stores the encrypted PIN blob used to refresh unlock material after unlock.
    async fn set_encrypted_pin(&self, encrypted_pin: EncString);
    /// Returns the encrypted PIN blob, if available.
    async fn get_encrypted_pin(&self) -> Option<EncString>;
    /// Clears the encrypted PIN blob.
    async fn clear_encrypted_pin(&self);
}

/// Thread-safe wrapper around the registered [`StateBridgeImpl`] instance.
#[derive(Clone)]
pub struct StateBridge {
    implementation: Arc<Mutex<Option<Arc<dyn StateBridgeImpl + Send + Sync>>>>,
}

macro_rules! call_state_bridge {
    ($self:expr, $method:ident $(, $arg:expr )* $(,)?) => {{
        let implementation = $self
            .implementation
            .lock()
            .expect("Mutex is not poisoned")
            .as_ref()
            .expect("StateBridge not registered")
            .clone();
        implementation.$method($($arg),*).await
    }};
}

impl StateBridge {
    /// Creates an empty bridge with no registered implementation.
    pub fn new() -> Self {
        Self {
            implementation: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns true if an implementation has been registered.
    pub fn is_registered(&self) -> bool {
        self.implementation
            .lock()
            .expect("Mutex is not poisoned")
            .is_some()
    }

    /// Registers the host-supplied implementation. Replaces any prior registration.
    pub fn register(&self, implementation: Box<dyn StateBridgeImpl + Send + Sync>) {
        *self.implementation.lock().expect("Mutex is not poisoned") = Some(implementation.into());
    }

    /// Stores the current decrypted user key.
    pub async fn set_user_key(&self, user_key: &SymmetricCryptoKey) {
        call_state_bridge!(self, set_user_key, user_key.to_owned());
    }

    /// Returns the current decrypted user key, if available.
    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        call_state_bridge!(self, get_user_key)
    }

    /// Clears any stored decrypted user key.
    pub async fn clear_user_key(&self) {
        call_state_bridge!(self, clear_user_key);
    }

    /// Stores the persistent PIN envelope.
    pub async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        call_state_bridge!(self, set_persistent_pin_envelope, pin_envelope);
    }

    /// Returns the persistent PIN envelope, if one exists.
    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        call_state_bridge!(self, get_persistent_pin_envelope)
    }

    /// Clears the persistent PIN envelope.
    pub async fn clear_persistent_pin_envelope(&self) {
        call_state_bridge!(self, clear_persistent_pin_envelope);
    }

    /// Stores the ephemeral PIN envelope for the current session.
    pub async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        call_state_bridge!(self, set_ephemeral_pin_envelope, pin_envelope);
    }

    /// Returns the ephemeral PIN envelope, if one exists.
    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        call_state_bridge!(self, get_ephemeral_pin_envelope)
    }

    /// Clears the ephemeral PIN envelope.
    pub async fn clear_ephemeral_pin_envelope(&self) {
        call_state_bridge!(self, clear_ephemeral_pin_envelope);
    }

    /// Stores the encrypted PIN blob.
    pub async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        call_state_bridge!(self, set_encrypted_pin, encrypted_pin);
    }

    /// Returns the encrypted PIN blob, if one exists.
    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        call_state_bridge!(self, get_encrypted_pin)
    }

    /// Clears the encrypted PIN blob.
    pub async fn clear_encrypted_pin(&self) {
        call_state_bridge!(self, clear_encrypted_pin);
    }
}

impl Default for StateBridge {
    fn default() -> Self {
        Self::new()
    }
}
