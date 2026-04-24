use async_trait::async_trait;
use bitwarden_crypto::{
    EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope,
};

#[allow(missing_docs)]
pub mod client;
#[cfg(feature = "wasm")]
mod wasm;

#[async_trait(?Send)]
#[allow(missing_docs)]
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
    pub(crate) implementation: Box<dyn StateBridgeImpl + Send + Sync>,
}
