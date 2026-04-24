use bitwarden_crypto::{Decryptable, EncString, safe::{PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeNamespace}};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{client::internal::InternalClient, key_management::SymmetricKeySlotId};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Determines where the PIN-protected user key envelope is stored.
pub enum PinLockType {
    /// Store the PIN envelope in persistent client-managed state.
    Persistent,
    /// Store the PIN envelope in ephemeral client-managed state.
    Ephemeral,
}

pub enum UnlockError {
    NoPinSet,
    PinWrong,
    InternalError,
}

struct PinUnlockSystem {
}

impl PinUnlockSystem {
    /// Retreives the currently active PIN envelope, preferring the ephemeral envelope if both are present.
    async fn get_active_pin_envelope(internal_client: &InternalClient) -> Option<PasswordProtectedKeyEnvelope> {
        let guard = internal_client.state_bridge.write().expect("Failed to acquire write lock on temporary state bridge");
        let state_bridge = guard.as_ref().expect("StateBridge not registered");
        let mut pin_protected_key_envelope = state_bridge.get_ephemeral_pin_envelope().await;
        if let None = pin_protected_key_envelope {
            pin_protected_key_envelope = state_bridge.get_persistent_pin_envelope().await;
        }
        pin_protected_key_envelope
    }

    pub(crate) async fn unlock(internal_client: &mut InternalClient, pin: &str) -> Result<(), UnlockError> {
        let pin_envelope = Self::get_active_pin_envelope(internal_client).await.ok_or(UnlockError::NoPinSet)?;

        // Unseal to key ctx
        let mut ctx = internal_client.get_key_store().context_mut();
        let key_slot = pin_envelope.unseal(pin, PasswordProtectedKeyEnvelopeNamespace::PinUnlock, &mut ctx)
            .map_err(|e| match e {
                bitwarden_crypto::safe::PasswordProtectedKeyEnvelopeError::WrongPassword => UnlockError::PinWrong,
                _ => UnlockError::InternalError,
            })?;

        // The key is currently in the local ctx and would be dropped when ctx goes out of scope. Persist it to the keystore
        ctx.persist_symmetric_key(key_slot, SymmetricKeySlotId::User)
            .map_err(|_| UnlockError::InternalError)
    }

    pub(crate) async fn on_unlock(internal_client: &mut InternalClient) -> Result<(), ()> {
        let encrypted_pin = internal_client.state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .get_encrypted_pin()
            .await;
    
        // If PIN unlock is not enabled, do nothing
        if encrypted_pin.is_none() {
            return Ok(());
        }

        // Make the fresh PIN envelope
        let pin_envelope = {
            let mut ctx = internal_client.get_key_store().context_mut();
            let pin: String = encrypted_pin
                .unwrap()
                .decrypt(&mut ctx, SymmetricKeySlotId::User)
                .map_err(|_| ())?;
            PasswordProtectedKeyEnvelope::seal(SymmetricKeySlotId::User, pin.as_str(), PasswordProtectedKeyEnvelopeNamespace::PinUnlock, &mut ctx)
                .expect("Failed to create PIN envelope")
        };

        // Store it to memory
        internal_client
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .await;
            .set_ephemeral_pin_envelope(pin_envelope);
        Ok(())
    }

        /// Sets the PIN and stores the generated envelope according to the lock type.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "setPin"))]
    pub async fn set_pin(internal_client: &InternalClient, pin: String, lock_type: PinLockType) -> Result<(), PinSettingsError> {
        let enroll_pin_response = internal_client
            .crypto()
            .enroll_pin(pin)
            .map_err(|_| PinSettingsError::SetPinState)?;
        let pin_envelope = enroll_pin_response.pin_protected_user_key_envelope;
        let encrypted_pin = enroll_pin_response.user_key_encrypted_pin;

        let mut state_bridge = internal_client.km_state_bridge();
        state_bridge.clear_persistent_pin_envelope().await;
        state_bridge.clear_ephemeral_pin_envelope().await;
        state_bridge.clear_encrypted_pin().await;
        state_bridge.set_encrypted_pin(encrypted_pin).await;

        match lock_type {
            PinLockType::Persistent => {
                state_bridge
                    .set_persistent_pin_envelope(pin_envelope)
                    .await;
            }
            PinLockType::Ephemeral => {
                state_bridge
                    .set_ephemeral_pin_envelope(pin_envelope)
                    .await;
            }
        }

        Ok(())
    }

    /// Clears both persistent and ephemeral PIN envelopes.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "unsetPin"))]
    pub async fn unset_pin(internal_client: &InternalClient) {
        let mut state_bridge = internal_client.km_state_bridge();
        state_bridge.clear_persistent_pin_envelope().await;
        state_bridge.clear_ephemeral_pin_envelope().await;
        state_bridge.clear_encrypted_pin().await;
    }

    /// Returns the lock type for the currently configured PIN.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "getPinLockType"))]
    pub async fn get_pin_lock_type(internal_client: &InternalClient) -> Option<PinLockType> {
        let state_bridge = internal_client.km_state_bridge();

        if state_bridge.get_persistent_pin_envelope().await.is_some() {
            return Some(PinLockType::Persistent);
        }

        if state_bridge.get_ephemeral_pin_envelope().await.is_some() {
            return Some(PinLockType::Ephemeral);
        }

        None
    }

    /// Indicates whether a PIN has been configured.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "isPinSet"))]
    pub async fn is_pin_set(internal_client: &InternalClient) -> bool {
        Self::get_pin_lock_type(internal_client).await.is_some()
    }

    /// Returns the configured PIN, if an encrypted PIN is available and decryptable.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "getPin"))]
    pub async fn get_pin(internal_client: &InternalClient) -> Option<String> {
        let state_bridge = internal_client.km_state_bridge();
        let encrypted_pin = state_bridge.get_encrypted_pin().await?;

        internal_client
            .crypto()
            .decrypt_encrypted_pin(encrypted_pin.to_string())
            .ok()
    }

    /// Indicates whether a PIN envelope is available for decryption (either persistent or ephemeral).
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "isPinDecryptionAvailable"))]
    pub async fn is_pin_decryption_available(internal_client: &InternalClient) -> bool {
        let state_bridge = internal_client.km_state_bridge();

        state_bridge.get_persistent_pin_envelope().await.is_some()
            || state_bridge.get_ephemeral_pin_envelope().await.is_some()
    }

    /// Validates that the provided PIN can decrypt the stored PIN envelope.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "validatePin"))]
    pub async fn validate_pin(internal_client: &InternalClient, pin: String) -> bool {
        let state_bridge = internal_client.km_state_bridge();

        // Try persistent envelope first, then ephemeral
        if let Some(envelope) = state_bridge.get_persistent_pin_envelope().await {
            return internal_client
                .crypto()
                .unseal_password_protected_key_envelope(pin, envelope)
                .is_ok();
        }

        if let Some(envelope) = state_bridge.get_ephemeral_pin_envelope().await {
            return internal_client
                .crypto()
                .unseal_password_protected_key_envelope(pin, envelope)
                .is_ok();
        }

        false
    }
}