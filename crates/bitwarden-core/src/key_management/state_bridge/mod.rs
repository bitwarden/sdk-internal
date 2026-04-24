use std::sync::RwLock;

use async_trait::async_trait;
use bitwarden_crypto::{
    EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope,
};

pub mod client;
#[cfg(feature = "wasm")]
mod wasm;

#[async_trait(?Send)]
pub trait StateBridgeImpl {
    async fn set_user_key(&mut self, user_key: &SymmetricCryptoKey);
    async fn get_user_key(&self) -> Option<SymmetricCryptoKey>;
    async fn clear_user_key(&mut self);

    async fn set_persistent_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope);
    async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    async fn clear_persistent_pin_envelope(&mut self);

    async fn set_ephemeral_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope);
    async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    async fn clear_ephemeral_pin_envelope(&mut self);

    async fn set_encrypted_pin(&mut self, encrypted_pin: EncString);
    async fn get_encrypted_pin(&self) -> Option<EncString>;
    async fn clear_encrypted_pin(&mut self);
}

pub struct StateBridge {
    implementation: RwLock<Option<Box<dyn StateBridgeImpl + Send + Sync>>>,
}

impl StateBridge {
    pub fn new() -> Self {
        Self {
            implementation: RwLock::new(None),
        }
    }

    /// Registers the host-supplied implementation. Replaces any prior registration.
    pub fn register(&self, implementation: Box<dyn StateBridgeImpl + Send + Sync>) {
        *self
            .implementation
            .write()
            .expect("RwLock is not poisoned") = Some(implementation);
    }

    pub async fn set_user_key(&self, user_key: &SymmetricCryptoKey) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .set_user_key(user_key)
            .await;
    }

    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .get_user_key()
            .await
    }

    pub async fn clear_user_key(&self) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_user_key()
            .await;
    }

    pub async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .get_persistent_pin_envelope()
            .await
    }

    pub async fn clear_persistent_pin_envelope(&self) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_persistent_pin_envelope()
            .await;
    }

    pub async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .get_ephemeral_pin_envelope()
            .await
    }

    pub async fn clear_ephemeral_pin_envelope(&self) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_ephemeral_pin_envelope()
            .await;
    }

    pub async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .set_encrypted_pin(encrypted_pin)
            .await;
    }

    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .get_encrypted_pin()
            .await
    }

    pub async fn clear_encrypted_pin(&self) {
        self.implementation
            .write()
            .expect("RwLock is not poisoned")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_encrypted_pin()
            .await;
    }
}
