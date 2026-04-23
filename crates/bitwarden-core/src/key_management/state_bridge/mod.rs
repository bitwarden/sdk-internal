use async_trait::async_trait;
use bitwarden_crypto::{SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};

#[allow(missing_docs)]
pub mod client;
#[cfg(feature = "wasm")]
mod wasm;

#[async_trait(?Send)]
#[allow(missing_docs)]
pub trait StateBridge {
    async fn set_user_key(&mut self, user_key: &SymmetricCryptoKey);
    async fn get_user_key(&self) -> Option<SymmetricCryptoKey>;
    async fn clear_user_key(&mut self);

    async fn set_persistent_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope);
    async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    async fn clear_persistent_pin_envelope(&mut self);

    async fn set_ephemeral_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope);
    async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope>;
    async fn clear_ephemeral_pin_envelope(&mut self);
}
