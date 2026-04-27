//! Pin-based unlock in Bitwarden works using a `PasswordProtectedKeyEnvelope`, which is sealed with
//! the PIN and contains the user-key. When unlocking with PIN, the envelope is unsealed with the
//! PIN and the key is loaded into the key-store.
//!
//! There are two modes of PIN-based unlock: Before-first-unlock (BFU) and after-first-unlock (AFU).
//! In BFU mode, the PIN envelope is persisted to disk. In AFU mode, the PIN envelope is only stored
//! in memory. The memory copy is always loaded into memory when transitioning from BFU to AFU mode
//! with an unlock.

#![allow(dead_code)]

use bitwarden_crypto::{
    Decryptable, KeyStore, PrimitiveEncryptable,
    safe::{PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeNamespace},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Client,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};

/// Pin unlock can be configured to use one of two modes. Before-first-unlock and
/// after-first-unlock. In AFU mode, the PIN is available only after unlocking once with the master
/// password or another unlock method. In BFU mode, PIN unlock is available right after app start.
/// For this, the PIN-encrypted vault key is stored on disk.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum PinLockType {
    /// Pin unlock is available after app start
    BeforeFirstUnlock,
    /// Pin unlock is available after unlocking with another method at least once during the app
    /// session
    AfterFirstUnlock,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Current availability state for PIN-based unlock.
pub enum PinUnlockStatus {
    /// A PIN is configured and the PIN envelope is available for decryption, so PIN-based unlock
    /// can be attempted.
    Available,
    /// A PIN is configured, but the vault must be unlocked using another method first.
    NeedsUnlock,
    /// No PIN is configured.
    NotSet,
}

pub(crate) enum UnlockError {
    NoPinSet,
    PinWrong,
    InternalError,
}

/// Provides PIN-based unlock functionality. This includes enrolling into PIN-based unlock,
/// unlocking using the PIN and handling necessary operations (PIN envelope refreshing when
/// transitioning to after-first-unlock mode).
pub struct PinLockSystem<'a> {
    client: &'a Client,
}

impl PinLockSystem<'_> {
    fn key_store(&self) -> &KeyStore<KeySlotIds> {
        self.client.internal.get_key_store()
    }

    /// Creates a PIN lock system view for a client instance.
    pub fn with_client(client: &Client) -> PinLockSystem<'_> {
        PinLockSystem { client }
    }

    /// Retrieves the currently active PIN envelope.
    ///
    /// If both envelopes are present, the ephemeral envelope is preferred.
    async fn get_active_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        let mut pin_protected_key_envelope = self.client.km_state_bridge().get_ephemeral_pin_envelope().await;
        if pin_protected_key_envelope.is_none() {
            pin_protected_key_envelope = self.client.km_state_bridge().get_persistent_pin_envelope().await;
        }
        pin_protected_key_envelope
    }

    /// Attempts to unlock the user key using `pin`.
    ///
    /// Returns [`UnlockError::NoPinSet`] if no PIN is configured,
    /// [`UnlockError::PinWrong`] if `pin` is incorrect, and
    /// [`UnlockError::InternalError`] for other failures.
    pub(crate) async fn unlock(&self, pin: &str) -> Result<(), UnlockError> {
        let pin_envelope = Self::get_active_pin_envelope(self)
            .await
            .ok_or(UnlockError::NoPinSet)?;

        // Unseal to key ctx
        let mut ctx = self.key_store().context_mut();
        let key_slot = pin_envelope
            .unseal(
                pin,
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &mut ctx,
            )
            .map_err(|e| match e {
                bitwarden_crypto::safe::PasswordProtectedKeyEnvelopeError::WrongPassword => {
                    UnlockError::PinWrong
                }
                _ => UnlockError::InternalError,
            })?;

        // The key is currently in the local ctx and would be dropped when ctx goes out of scope.
        // Persist it to the keystore
        ctx.persist_symmetric_key(key_slot, SymmetricKeySlotId::User)
            .map_err(|_| UnlockError::InternalError)
    }

    /// Refreshes in-memory PIN unlock material after a successful non-PIN unlock.
    ///
    /// This recreates the ephemeral PIN envelope from the encrypted PIN, when available.
    pub(crate) async fn on_unlock(&self) -> Result<(), ()> {
        let encrypted_pin = self.client.km_state_bridge().get_encrypted_pin().await;

        // If PIN unlock is not enabled, do nothing
        let Some(encrypted_pin) = encrypted_pin else {
            return Ok(());
        };

        // Make the fresh PIN envelope
        let pin_envelope = {
            let mut ctx = self.key_store().context_mut();
            let pin: String = encrypted_pin
                .decrypt(&mut ctx, SymmetricKeySlotId::User)
                .map_err(|_| ())?;
            PasswordProtectedKeyEnvelope::seal(
                SymmetricKeySlotId::User,
                pin.as_str(),
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("Failed to create PIN envelope")
        };

        // Store it to memory
        self.client
            .km_state_bridge()
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;

        Ok(())
    }

    /// Sets the PIN and stores the generated envelope according to the lock type.
    pub async fn set_pin(&self, pin: String, lock_type: PinLockType) -> Result<(), ()> {
        // Clear the existing configuration
        self.client
            .km_state_bridge()
            .clear_persistent_pin_envelope()
            .await;
        self.client
            .km_state_bridge()
            .clear_ephemeral_pin_envelope()
            .await;
        self.client.km_state_bridge().clear_encrypted_pin().await;

        let pin_envelope: PasswordProtectedKeyEnvelope = PasswordProtectedKeyEnvelope::seal(
            SymmetricKeySlotId::User,
            pin.as_str(),
            PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
            &self.key_store().context_mut(),
        )
        .map_err(|_| ())?;
        let encrypted_pin = pin
            .encrypt(
                &mut self.key_store().context_mut(),
                SymmetricKeySlotId::User,
            )
            .map_err(|_| ())?;

        self.client
            .km_state_bridge()
            .set_encrypted_pin(encrypted_pin)
            .await;
        self.client
            .km_state_bridge()
            .set_ephemeral_pin_envelope(pin_envelope.clone())
            .await;

        if lock_type == PinLockType::BeforeFirstUnlock {
            self.client
                .km_state_bridge()
                .set_persistent_pin_envelope(pin_envelope)
                .await;
        }

        Ok(())
    }

    /// Clears both persistent and ephemeral PIN envelopes.
    pub async fn unset_pin(&self) {
        self.client
            .km_state_bridge()
            .clear_persistent_pin_envelope()
            .await;
        self.client
            .km_state_bridge()
            .clear_ephemeral_pin_envelope()
            .await;
        self.client.km_state_bridge().clear_encrypted_pin().await;
    }

    /// Returns the lock type for the currently configured PIN.
    pub async fn get_pin_lock_type(&self) -> Option<PinLockType> {
        if self
            .client
            .km_state_bridge()
            .get_persistent_pin_envelope()
            .await
            .is_some()
        {
            return Some(PinLockType::BeforeFirstUnlock);
        }

        if self
            .client
            .km_state_bridge()
            .get_ephemeral_pin_envelope()
            .await
            .is_some()
        {
            return Some(PinLockType::AfterFirstUnlock);
        }

        None
    }

    /// Returns the current PIN unlock status.
    ///
    /// If a lock type is configured but no ephemeral envelope is currently present,
    /// the status is [`PinUnlockStatus::NeedsUnlock`].
    pub async fn get_pin_status(&self) -> PinUnlockStatus {
        if Self::get_pin_lock_type(self).await.is_some() {
            if self
                .client
                .km_state_bridge()
                .get_ephemeral_pin_envelope()
                .await
                .is_some()
            {
                PinUnlockStatus::Available
            } else {
                PinUnlockStatus::NeedsUnlock
            }
        } else {
            PinUnlockStatus::NotSet
        }
    }

    /// Returns the configured PIN, if an encrypted PIN is available and decryptable.
    pub async fn get_pin(&self) -> Option<String> {
        let encrypted_pin = self.client.km_state_bridge().get_encrypted_pin().await?;
        encrypted_pin
            .decrypt(
                &mut self.client.internal.get_key_store().context_mut(),
                SymmetricKeySlotId::User,
            )
            .ok()
    }

    /// Validates that the provided PIN can decrypt the stored PIN envelope.
    pub async fn validate_pin(&self, pin: String) -> bool {
        let pin_envelope = self.get_active_pin_envelope().await;
        let Some(pin_envelope) = pin_envelope else {
            return false;
        };

        pin_envelope
            .unseal(
                pin.as_str(),
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &mut self.key_store().context_mut(),
            )
            .is_ok()
    }
}
