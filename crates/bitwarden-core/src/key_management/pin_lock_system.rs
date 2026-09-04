//! Pin-based unlock in Bitwarden works using a `PasswordProtectedKeyEnvelope`, which is sealed with
//! the PIN and contains the user-key. When unlocking with PIN, the envelope is unsealed with the
//! PIN and the key is loaded into the key-store.
//!
//! There are two modes of PIN-based unlock: Before-first-unlock (BFU) and after-first-unlock (AFU).
//! In BFU mode, the PIN envelope is persisted to disk. In AFU mode, the PIN envelope is only stored
//! in memory. The memory copy is always loaded into memory when transitioning from BFU to AFU mode
//! with an unlock.

use bitwarden_crypto::{
    Decryptable, KeyId, KeyStore, PrimitiveEncryptable, SymmetricKeyAlgorithm,
    safe::{PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeNamespace},
};
use serde::{Deserialize, Serialize};
use tracing::warn;
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
#[bitwarden_ffi::wasm_record]
pub enum PinLockType {
    /// Pin unlock is available after app start
    BeforeFirstUnlock,
    /// Pin unlock is available after unlocking with another method at least once during the app
    /// session
    AfterFirstUnlock,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MigrationFailed {
    /// Vault is locked
    Locked,
    /// Could not read the contained key id from the persistent envelope.
    EnvelopeMalformed,
    /// Envelope and user key are both V2, but the key ids differ.
    /// V2 -> V2 key rotation is not currently supported here.
    V2KeyRotationUnsupported,
    /// The envelope holds a key that is not the current V1 user key, and no recovery path exists.
    EnvelopeWithKeyIdWithV1UserKey,
    /// V1 -> V2 migration is required but no V2 upgrade token is stored.
    MissingV2UpgradeToken,
    /// Re-enrollment is required but no encrypted PIN is stored.
    MissingEncryptedPin,
    /// Re-enrollment could not decrypt the encrypted PIN.
    PinDecryption,
    /// Re-sealing the envelope under the new user key failed.
    Reenrollment,
}

/// What [`PinLockSystem::migrate_pin_envelope_if_needed`] should do with the persistent PIN
/// envelope, decided from key ids alone.
#[derive(Debug, PartialEq, Eq)]
enum PinEnvelopeAction {
    /// The envelope already holds the current user key. Nothing to do.
    UpToDate,
    /// The envelope holds the current V1 user key but was sealed before V1 keys had derived key
    /// ids, so it carries none. Re-enroll under the same key so the envelope gains one. This is
    /// not a key change and needs no upgrade token.
    BackfillKeyId,
    /// The envelope holds the previous V1 user key. Re-enroll under the current V2 user key. The
    /// upgrade token is used to confirm the envelope really is V1 before anything is rewritten.
    MigrateV1ToV2,
    /// Terminal failure; no migration is possible.
    Failed(MigrationFailed),
}

/// Decides what to do with the persistent PIN envelope.
///
/// - No key id at all means the envelope predates derived key ids, which means it was sealed under
///   a V1 key — V2 keys have always had one.
/// - A key id that differs from the user key's is ambiguous, and only the V2 upgrade token can
///   resolve it.
fn classify_pin_envelope(
    envelope_key_id: Option<&KeyId>,
    current_user_key_id: &KeyId,
    user_key_is_v1: bool,
) -> PinEnvelopeAction {
    match envelope_key_id {
        Some(envelope_key_id) if envelope_key_id == current_user_key_id => {
            PinEnvelopeAction::UpToDate
        }
        None if user_key_is_v1 => PinEnvelopeAction::BackfillKeyId,
        None => PinEnvelopeAction::MigrateV1ToV2,
        Some(_) if user_key_is_v1 => {
            PinEnvelopeAction::Failed(MigrationFailed::EnvelopeWithKeyIdWithV1UserKey)
        }
        Some(_) => PinEnvelopeAction::MigrateV1ToV2,
    }
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
        let mut pin_protected_key_envelope = self
            .client
            .km_state_bridge()
            .get_ephemeral_pin_envelope()
            .await;
        if pin_protected_key_envelope.is_none() {
            pin_protected_key_envelope = self
                .client
                .km_state_bridge()
                .get_persistent_pin_envelope()
                .await;
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

    /// Brings the persistent PIN envelope in line with the current user key.
    ///
    /// This covers two cases, both of which end in a fresh enrollment and differ only in how the
    /// previous PIN is recovered:
    ///
    /// - After a V2 upgrade, when a V2 upgrade token is present and the persistent PIN envelope is
    ///   still encrypted with the V1 user key, the enrollment is migrated to the current user key.
    /// - When the envelope was sealed before V1 keys had derived key ids, it is re-enrolled under
    ///   the same, unchanged key so that it gains one.
    ///
    /// See [`classify_pin_envelope`] for how the two are told apart.
    async fn migrate_pin_envelope_if_needed(&self) -> Result<(), MigrationFailed> {
        let Some(envelope) = self
            .client
            .km_state_bridge()
            .get_persistent_pin_envelope()
            .await
        else {
            return Ok(());
        };

        let envelope_key_id = envelope
            .contained_key_id()
            .map_err(|_| MigrationFailed::EnvelopeMalformed)?;
        // Scoped so the context is dropped before the awaits below.
        let (current_user_key_id, user_key_is_v1) = {
            let ctx = self.key_store().context();
            (
                ctx.get_symmetric_key_id(SymmetricKeySlotId::User)
                    .ok_or(MigrationFailed::Locked)?,
                matches!(
                    ctx.get_symmetric_key_algorithm(SymmetricKeySlotId::User),
                    Ok(SymmetricKeyAlgorithm::Aes256CbcHmac)
                ),
            )
        };

        // Recover the previous PIN, in the way the classified action calls for.
        let pin: String = match classify_pin_envelope(
            envelope_key_id.as_ref(),
            &current_user_key_id,
            user_key_is_v1,
        ) {
            PinEnvelopeAction::UpToDate => return Ok(()),
            PinEnvelopeAction::Failed(error) => return Err(error),

            // The user key has not changed, so the stored PIN is still encrypted under it.
            PinEnvelopeAction::BackfillKeyId => {
                let encrypted_pin = self
                    .client
                    .km_state_bridge()
                    .get_encrypted_pin()
                    .await
                    .ok_or(MigrationFailed::MissingEncryptedPin)?;
                encrypted_pin
                    .decrypt(
                        &mut self.key_store().context_mut(),
                        SymmetricKeySlotId::User,
                    )
                    .map_err(|_| MigrationFailed::PinDecryption)?
            }

            // The stored PIN is encrypted under the previous V1 user key, which has to be
            // recovered from the upgrade token first.
            PinEnvelopeAction::MigrateV1ToV2 => {
                let token = self
                    .client
                    .km_state_bridge()
                    .get_v2_upgrade_token()
                    .await
                    .ok_or(MigrationFailed::MissingV2UpgradeToken)?;
                let encrypted_pin = self
                    .client
                    .km_state_bridge()
                    .get_encrypted_pin()
                    .await
                    .ok_or(MigrationFailed::MissingEncryptedPin)?;

                // The unwrapped V1 key only lives in this context, so unwrapping it, identifying
                // the envelope with it, and decrypting the PIN all have to share one context.
                let mut ctx = self.key_store().context_mut();
                let v1_slot = token
                    .unwrap_v1(SymmetricKeySlotId::User, &mut ctx)
                    .map_err(|_| MigrationFailed::PinDecryption)?;

                // A V1 envelope holds the key the upgrade token unwraps. An envelope with no key id
                // predates derived key ids and is taken to be V1; one holding any other
                // key is a V2 -> V2 rotation.
                if envelope_key_id.is_some() && envelope_key_id != ctx.get_symmetric_key_id(v1_slot)
                {
                    return Err(MigrationFailed::V2KeyRotationUnsupported);
                }

                encrypted_pin
                    .decrypt(&mut ctx, v1_slot)
                    .map_err(|_| MigrationFailed::PinDecryption)?
            }
        };

        // Do a fresh enrollment with the current user-key
        self.set_pin(pin, PinLockType::BeforeFirstUnlock)
            .await
            .map_err(|_| MigrationFailed::Reenrollment)?;

        Ok(())
    }

    /// Refreshes in-memory PIN unlock material after a successful non-PIN unlock.
    ///
    /// This recreates the ephemeral PIN envelope from the encrypted PIN, when available.
    pub(crate) async fn on_unlock(&self) {
        // Remove once all clients, ios, android implement the state bridge
        if !self.client.km_state_bridge().is_bridge_registered() {
            return;
        }

        if let Err(e) = self.migrate_pin_envelope_if_needed().await {
            warn!("PIN migration failed: {e:?}, unenrolling PIN");
            self.unset_pin().await;
            return;
        }

        let encrypted_pin = self.client.km_state_bridge().get_encrypted_pin().await;

        // If PIN unlock is not enabled, do nothing
        let Some(encrypted_pin) = encrypted_pin else {
            return;
        };

        // Make the fresh PIN envelope
        let Ok(pin_envelope) = (|| -> Result<PasswordProtectedKeyEnvelope, ()> {
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
            .map_err(|_| ())
        })() else {
            warn!("Failed to create PIN envelope");
            return;
        };

        // Store it to memory
        self.client
            .km_state_bridge()
            .set_ephemeral_pin_envelope(&pin_envelope)
            .await;
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
            .set_encrypted_pin(&encrypted_pin)
            .await;
        self.client
            .km_state_bridge()
            .set_ephemeral_pin_envelope(&pin_envelope)
            .await;

        if lock_type == PinLockType::BeforeFirstUnlock {
            self.client
                .km_state_bridge()
                .set_persistent_pin_envelope(&pin_envelope)
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

        // Encrypted pin is set for either lock type, persistent pin only for BFU. The ephemeral
        // envelope may not be set after restarting a client, until the client enters AFU
        // mode.
        if self
            .client
            .km_state_bridge()
            .get_encrypted_pin()
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
        match Self::get_pin_lock_type(self).await {
            Some(PinLockType::BeforeFirstUnlock) => {
                if self.get_active_pin_envelope().await.is_some() {
                    PinUnlockStatus::Available
                } else {
                    PinUnlockStatus::NeedsUnlock
                }
            }
            Some(PinLockType::AfterFirstUnlock) => {
                if self
                    .client
                    .km_state_bridge()
                    .get_ephemeral_pin_envelope()
                    .await
                    .is_some()
                {
                    PinUnlockStatus::Available
                } else {
                    // This should not happen as AFU should always have the ephemeral envelope, but
                    // we handle it just in case.
                    PinUnlockStatus::NeedsUnlock
                }
            }
            None => PinUnlockStatus::NotSet,
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

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{EncString, KeyId, SymmetricKeyAlgorithm};

    use super::*;
    use crate::key_management::{V2UpgradeToken, state_bridge::test_support::InMemoryStateBridge};

    fn decrypt_encrypted_pin(client: &Client, encrypted_pin: &EncString) -> String {
        encrypted_pin
            .decrypt(
                &mut client.internal.get_key_store().context_mut(),
                SymmetricKeySlotId::User,
            )
            .expect("encrypted pin should decrypt successfully")
    }

    /// The PIN [`TESTVECTOR_LEGACY_ENVELOPE`] was sealed with.
    const TESTVECTOR_LEGACY_ENVELOPE_PIN: &str = "1234";
    /// A `PinUnlock` envelope sealed under an AES-CBC-HMAC (V1) key by a client predating derived
    /// key ids, so it carries no contained key id.
    ///
    /// The migration never unseals this envelope — it reads the contained key id and then
    /// re-enrolls from the key store — so the key sealed inside is arbitrary and deliberately
    /// unrelated to the user key the tests install.
    ///
    /// The current seal path always writes a contained key id, so re-recording this requires
    /// temporarily changing `set_contained_key_id(&mut header, key_to_seal.key_id())` in
    /// `bitwarden-crypto/src/safe/password_protected_key_envelope.rs` to pass `None`, sealing a
    /// `PinUnlock` envelope for an `Aes256CbcHmac` key with [`TESTVECTOR_LEGACY_ENVELOPE_PIN`],
    /// printing `Vec::from(&envelope)`, and then reverting that change.
    const TESTVECTOR_LEGACY_ENVELOPE: &[u8] = &[
        132, 88, 52, 164, 1, 3, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47,
        120, 46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45,
        107, 101, 121, 58, 0, 1, 56, 129, 1, 58, 0, 1, 56, 128, 1, 161, 5, 76, 148, 49, 223, 205,
        195, 252, 91, 216, 65, 200, 121, 104, 88, 80, 89, 120, 16, 161, 14, 97, 191, 97, 138, 42,
        102, 234, 49, 186, 2, 255, 31, 4, 232, 178, 100, 53, 37, 181, 172, 129, 193, 51, 109, 8,
        160, 29, 254, 181, 242, 102, 73, 229, 89, 150, 227, 252, 120, 156, 71, 202, 200, 241, 74,
        241, 206, 16, 155, 83, 49, 242, 13, 209, 10, 217, 251, 164, 244, 69, 41, 52, 9, 192, 140,
        248, 251, 244, 84, 154, 15, 100, 222, 102, 117, 185, 129, 131, 71, 161, 1, 58, 0, 1, 21,
        87, 165, 1, 58, 0, 1, 21, 87, 58, 0, 1, 21, 89, 3, 58, 0, 1, 21, 90, 26, 0, 1, 0, 0, 58, 0,
        1, 21, 91, 4, 58, 0, 1, 21, 88, 80, 64, 184, 87, 20, 40, 186, 214, 56, 87, 53, 118, 100, 5,
        21, 13, 3, 246,
    ];

    /// Parses [`TESTVECTOR_LEGACY_ENVELOPE`], asserting it really has no contained key id.
    fn legacy_envelope() -> PasswordProtectedKeyEnvelope {
        let envelope = PasswordProtectedKeyEnvelope::try_from(&TESTVECTOR_LEGACY_ENVELOPE.to_vec())
            .expect("legacy envelope test vector parses");
        assert_eq!(
            envelope.contained_key_id().expect("readable"),
            None,
            "legacy envelope test vector must have no contained key id",
        );
        envelope
    }

    /// Returns the `KeyId` of the symmetric key currently in `SymmetricKeySlotId::User`.
    fn user_key_id(client: &Client) -> KeyId {
        client
            .internal
            .get_key_store()
            .context()
            .get_symmetric_key_id(SymmetricKeySlotId::User)
            .expect("user key present")
    }

    /// Asserts the envelope wraps `expected_key_id` and unseals successfully under `pin`.
    fn assert_envelope_wraps_user_key(
        client: &Client,
        envelope: &PasswordProtectedKeyEnvelope,
        pin: &str,
        expected_key_id: &KeyId,
    ) {
        assert_eq!(
            envelope
                .contained_key_id()
                .expect("contained key id readable"),
            Some(expected_key_id.clone()),
            "envelope wraps a key other than the current user key",
        );
        let _ = envelope
            .unseal(
                pin,
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &mut client.internal.get_key_store().context_mut(),
            )
            .expect("envelope unseals with the configured pin");
    }

    fn client_with_user_key() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .expect("persisting user key should succeed");
        }
        client
    }

    fn seal_envelope(client: &Client, pin: &str) -> PasswordProtectedKeyEnvelope {
        PasswordProtectedKeyEnvelope::seal(
            SymmetricKeySlotId::User,
            pin,
            PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
            &client.internal.get_key_store().context_mut(),
        )
        .expect("seal succeeds")
    }

    #[tokio::test]
    async fn set_pin_bfu_persists_both_envelopes() {
        let client = client_with_user_key();
        let user_key_id = user_key_id(&client);
        let system = PinLockSystem::with_client(&client);

        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        let bridge = client.km_state_bridge();
        let persistent = bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope present");
        let ephemeral = bridge
            .get_ephemeral_pin_envelope()
            .await
            .expect("ephemeral envelope present");
        let encrypted_pin = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin present");

        assert_envelope_wraps_user_key(&client, &persistent, "1234", &user_key_id);
        assert_envelope_wraps_user_key(&client, &ephemeral, "1234", &user_key_id);
        assert_eq!(decrypt_encrypted_pin(&client, &encrypted_pin), "1234");

        assert_eq!(
            system.get_pin_lock_type().await,
            Some(PinLockType::BeforeFirstUnlock)
        );
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::Available);
    }

    #[tokio::test]
    async fn set_pin_afu_persists_only_ephemeral() {
        let client = client_with_user_key();
        let user_key_id = user_key_id(&client);
        let system = PinLockSystem::with_client(&client);

        system
            .set_pin("1234".into(), PinLockType::AfterFirstUnlock)
            .await
            .expect("set_pin succeeds");

        let bridge = client.km_state_bridge();
        assert!(bridge.get_persistent_pin_envelope().await.is_none());
        let ephemeral = bridge
            .get_ephemeral_pin_envelope()
            .await
            .expect("ephemeral envelope present");
        let encrypted_pin = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin present");

        assert_envelope_wraps_user_key(&client, &ephemeral, "1234", &user_key_id);
        assert_eq!(decrypt_encrypted_pin(&client, &encrypted_pin), "1234");

        assert_eq!(
            system.get_pin_lock_type().await,
            Some(PinLockType::AfterFirstUnlock)
        );
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::Available);
    }

    #[tokio::test]
    async fn set_pin_overwrites_existing_state() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        system
            .set_pin("first".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("first set_pin");
        system
            .set_pin("second".into(), PinLockType::AfterFirstUnlock)
            .await
            .expect("second set_pin");

        let bridge = client.km_state_bridge();
        assert!(
            bridge.get_persistent_pin_envelope().await.is_none(),
            "switching to AFU must clear the persistent envelope"
        );
        assert_eq!(
            system.get_pin_lock_type().await,
            Some(PinLockType::AfterFirstUnlock)
        );
        assert!(system.validate_pin("second".into()).await);
        assert!(!system.validate_pin("first".into()).await);
    }

    #[tokio::test]
    async fn unset_pin_clears_all_state() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");
        system.unset_pin().await;

        let bridge = client.km_state_bridge();
        assert!(bridge.get_persistent_pin_envelope().await.is_none());
        assert!(bridge.get_ephemeral_pin_envelope().await.is_none());
        assert!(bridge.get_encrypted_pin().await.is_none());
        assert_eq!(system.get_pin_lock_type().await, None);
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::NotSet);
    }

    #[tokio::test]
    async fn unlock_with_correct_pin_persists_user_key() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        let pre_unlock_user_key_id = user_key_id(&client);
        // Snapshot ciphertext under the original user key, then drop the key from memory.
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");
        client.internal.get_key_store().clear();

        assert!(system.unlock("1234").await.is_ok());
        let post_unlock_user_key_id = user_key_id(&client);
        assert_eq!(post_unlock_user_key_id, pre_unlock_user_key_id);
    }

    #[tokio::test]
    async fn unlock_with_wrong_pin_returns_pin_wrong() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        assert!(matches!(
            system.unlock("wrong").await,
            Err(UnlockError::PinWrong)
        ));
    }

    #[tokio::test]
    async fn unlock_with_no_pin_set_returns_no_pin_set() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        assert!(matches!(
            system.unlock("anything").await,
            Err(UnlockError::NoPinSet)
        ));
    }

    #[tokio::test]
    async fn unlock_prefers_ephemeral_envelope_over_persistent() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("persistent".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        // Replace the ephemeral envelope with one sealed under a different PIN
        // (same user key still in the slot).
        let ephemeral = seal_envelope(&client, "ephemeral");
        client
            .km_state_bridge()
            .set_ephemeral_pin_envelope(&ephemeral)
            .await;

        assert!(system.unlock("ephemeral").await.is_ok());
        assert!(matches!(
            system.unlock("persistent").await,
            Err(UnlockError::PinWrong)
        ));
    }

    #[tokio::test]
    async fn get_pin_status_available_bfu() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        // Simulate app restart: ephemeral memory state is gone, only persisted disk state remains.
        client
            .km_state_bridge()
            .clear_ephemeral_pin_envelope()
            .await;

        assert_eq!(system.get_pin_status().await, PinUnlockStatus::Available);
        assert_eq!(
            system.get_pin_lock_type().await,
            Some(PinLockType::BeforeFirstUnlock)
        );
    }

    #[tokio::test]
    async fn on_unlock_rebuilds_ephemeral_envelope() {
        let client = client_with_user_key();
        let user_key_id = user_key_id(&client);
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::AfterFirstUnlock)
            .await
            .expect("set_pin succeeds");
        client
            .km_state_bridge()
            .clear_ephemeral_pin_envelope()
            .await;
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::NeedsUnlock);

        system.on_unlock().await;

        let rebuilt = client
            .km_state_bridge()
            .get_ephemeral_pin_envelope()
            .await
            .expect("on_unlock should restore the ephemeral envelope");
        assert_envelope_wraps_user_key(&client, &rebuilt, "1234", &user_key_id);
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::Available);
        assert!(system.unlock("1234").await.is_ok());
    }

    #[tokio::test]
    async fn on_unlock_is_noop_when_no_encrypted_pin() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        system.on_unlock().await;

        assert_eq!(system.get_pin_status().await, PinUnlockStatus::NotSet);
    }

    #[tokio::test]
    async fn on_unlock_is_noop_when_bridge_not_registered() {
        let client = Client::new(None);
        let system = PinLockSystem::with_client(&client);

        // Must not panic even though no StateBridgeImpl is registered.
        system.on_unlock().await;
    }

    #[tokio::test]
    async fn get_pin_returns_set_pin() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        assert_eq!(system.get_pin().await, None);

        system
            .set_pin("1234".into(), PinLockType::AfterFirstUnlock)
            .await
            .expect("set_pin succeeds");
        assert_eq!(system.get_pin().await, Some("1234".to_owned()));

        system.unset_pin().await;
        assert_eq!(system.get_pin().await, None);
    }

    #[tokio::test]
    async fn validate_pin_matches_only_correct_pin() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        assert!(!system.validate_pin("anything".into()).await);

        system
            .set_pin("1234".into(), PinLockType::AfterFirstUnlock)
            .await
            .expect("set_pin succeeds");
        assert!(system.validate_pin("1234".into()).await);
        assert!(!system.validate_pin("wrong".into()).await);
    }

    /// Snapshot of the persisted state a client would have after a V1→V2 user-key upgrade,
    /// before the PIN envelope has been re-sealed.
    struct V1State {
        envelope: PasswordProtectedKeyEnvelope,
        encrypted_pin: EncString,
        token: V2UpgradeToken,
    }

    /// Builds a client with a V2 user key in the `User` slot plus the disk-shaped artifacts
    /// of a prior V1 PIN enrollment: a V1 key sealed in a PIN envelope, an encrypted PIN under that
    /// V1 key, and a V2 upgrade token tying the two.
    fn fresh_v1_state_with_v2_user_key(pin: &str) -> (Client, V1State) {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));

        let state = {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();

            let v1_local = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let v2_local = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

            let envelope = PasswordProtectedKeyEnvelope::seal(
                v1_local,
                pin,
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("v1 envelope seals");
            let encrypted_pin = pin
                .encrypt(&mut ctx, v1_local)
                .expect("pin encrypts under v1 key");
            let token =
                V2UpgradeToken::create(v1_local, v2_local, &ctx).expect("upgrade token created");

            ctx.persist_symmetric_key(v2_local, SymmetricKeySlotId::User)
                .expect("persisting v2 user key succeeds");

            V1State {
                envelope,
                encrypted_pin,
                token,
            }
        };

        (client, state)
    }

    /// Like `client_with_user_key`, but installs a V1 (Aes256CbcHmac) user key, so
    /// `get_symmetric_key_id(User)` returns `None`.
    fn client_with_v1_user_key() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let user_key = ctx.generate_symmetric_key();
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .expect("persisting v1 user key should succeed");
        }
        client
    }

    fn assert_pin_envelopes_equal(
        envelope_1: &PasswordProtectedKeyEnvelope,
        envelope_2: &PasswordProtectedKeyEnvelope,
    ) {
        assert_eq!(
            serde_json::to_string(envelope_1).expect("envelope serializes"),
            serde_json::to_string(envelope_2).expect("envelope serializes"),
            "envelopes should be identical",
        );
    }

    async fn assert_pin_fully_unenrolled(client: &Client) {
        let bridge = client.km_state_bridge();
        assert!(bridge.get_persistent_pin_envelope().await.is_none());
        assert!(bridge.get_ephemeral_pin_envelope().await.is_none());
        assert!(bridge.get_encrypted_pin().await.is_none());
        assert_eq!(
            PinLockSystem::with_client(client).get_pin_status().await,
            PinUnlockStatus::NotSet,
        );
    }

    // ------------------------------------------------------------------------------------
    // PIN envelope migration
    //
    // These follow the cases in `classify_pin_envelope`: the classifier in isolation first, then
    // each action and failure branch end to end, in the same order.
    // ------------------------------------------------------------------------------------

    fn test_key_id(byte: u8) -> KeyId {
        KeyId::from([byte; 16])
    }

    #[test]
    fn classify_matching_key_id_is_up_to_date() {
        for user_key_is_v1 in [true, false] {
            assert_eq!(
                classify_pin_envelope(Some(&test_key_id(1)), &test_key_id(1), user_key_is_v1),
                PinEnvelopeAction::UpToDate,
                "user_key_is_v1 = {user_key_is_v1}",
            );
        }
    }

    #[test]
    fn classify_missing_envelope_key_id_with_v1_user_key_backfills() {
        assert_eq!(
            classify_pin_envelope(None, &test_key_id(1), true),
            PinEnvelopeAction::BackfillKeyId,
        );
    }

    #[test]
    fn classify_missing_envelope_key_id_with_v2_user_key_migrates() {
        assert_eq!(
            classify_pin_envelope(None, &test_key_id(1), false),
            PinEnvelopeAction::MigrateV1ToV2,
        );
    }

    #[test]
    fn classify_differing_key_id_with_v1_user_key_fails() {
        assert_eq!(
            classify_pin_envelope(Some(&test_key_id(1)), &test_key_id(2), true),
            PinEnvelopeAction::Failed(MigrationFailed::EnvelopeWithKeyIdWithV1UserKey),
        );
    }

    #[test]
    fn classify_differing_key_id_with_v2_user_key_migrates() {
        assert_eq!(
            classify_pin_envelope(Some(&test_key_id(1)), &test_key_id(2), false),
            PinEnvelopeAction::MigrateV1ToV2,
        );
    }

    /// Classification needs a user key to compare against, so a locked vault is rejected before
    /// [`classify_pin_envelope`] is reached.
    #[tokio::test]
    async fn migrate_without_user_key_fails_locked() {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
            .km_state_bridge()
            .set_persistent_pin_envelope(&legacy_envelope())
            .await;

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::Locked),
        );
    }

    #[tokio::test]
    async fn migrate_without_persistent_envelope_is_noop() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);

        system
            .migrate_pin_envelope_if_needed()
            .await
            .expect("migration succeeds");

        assert_pin_fully_unenrolled(&client).await;
    }

    /// The envelope already holds the current V2 user key.
    #[tokio::test]
    async fn migrate_up_to_date_v2_envelope_is_noop() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        let bridge = client.km_state_bridge();
        let persistent_before = &bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope present");
        let ephemeral_before = &bridge
            .get_ephemeral_pin_envelope()
            .await
            .expect("ephemeral envelope present");
        let encrypted_pin_before = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin present")
            .to_string();

        system
            .migrate_pin_envelope_if_needed()
            .await
            .expect("migration succeeds");

        let persistent_after = &bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope still present");
        let ephemeral_after = &bridge
            .get_ephemeral_pin_envelope()
            .await
            .expect("ephemeral envelope still present");
        let encrypted_pin_after = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin still present")
            .to_string();

        assert_pin_envelopes_equal(persistent_before, persistent_after);
        assert_pin_envelopes_equal(ephemeral_before, ephemeral_after);
        assert_eq!(encrypted_pin_before, encrypted_pin_after);
    }

    /// A V1 envelope sealed by a current client carries the V1 key's derived key id, so it
    /// already matches the user key.
    #[tokio::test]
    async fn migrate_up_to_date_v1_envelope_is_noop() {
        let pin = "1234";
        let client = client_with_v1_user_key();
        let envelope = seal_envelope(&client, pin);
        let encrypted_pin = pin
            .encrypt(
                &mut client.internal.get_key_store().context_mut(),
                SymmetricKeySlotId::User,
            )
            .expect("encrypt under v1 user key");

        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&envelope).await;
        bridge.set_encrypted_pin(&encrypted_pin).await;

        assert_eq!(
            envelope.contained_key_id().expect("readable"),
            Some(user_key_id(&client)),
            "a freshly sealed V1 envelope carries the V1 key's derived key id",
        );

        let persistent_before = &envelope;
        let encrypted_pin_before = encrypted_pin.to_string();

        let system = PinLockSystem::with_client(&client);
        system
            .migrate_pin_envelope_if_needed()
            .await
            .expect("migration succeeds");

        let persistent_after = &bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope still present");
        let encrypted_pin_after = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin still present")
            .to_string();
        assert_pin_envelopes_equal(persistent_before, persistent_after);
        assert_eq!(encrypted_pin_before, encrypted_pin_after);
        assert!(bridge.get_ephemeral_pin_envelope().await.is_none());
    }

    /// The envelope predates derived key ids and the user key is unchanged, so it is re-enrolled
    /// under that same key purely to gain a key id. This is the state every existing V1 PIN user
    /// is in, so it must never fail the unlock.
    #[tokio::test]
    async fn migrate_legacy_envelope_with_v1_user_key_backfills_key_id() {
        let pin = TESTVECTOR_LEGACY_ENVELOPE_PIN;
        let client = client_with_v1_user_key();
        let encrypted_pin = pin
            .encrypt(
                &mut client.internal.get_key_store().context_mut(),
                SymmetricKeySlotId::User,
            )
            .expect("encrypt under v1 user key");

        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&legacy_envelope()).await;
        bridge.set_encrypted_pin(&encrypted_pin).await;

        let user_key_id = user_key_id(&client);
        let system = PinLockSystem::with_client(&client);
        system
            .migrate_pin_envelope_if_needed()
            .await
            .expect("migration succeeds");

        let persistent = bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope present after backfill");
        assert_envelope_wraps_user_key(&client, &persistent, pin, &user_key_id);
        assert!(system.unlock(pin).await.is_ok());
    }

    /// A backfill with no PIN to re-enroll with.
    #[tokio::test]
    async fn migrate_legacy_envelope_with_v1_user_key_without_encrypted_pin_fails() {
        let client = client_with_v1_user_key();
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&legacy_envelope()).await;
        // Intentionally omit set_encrypted_pin.

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::MissingEncryptedPin),
        );
    }

    /// The envelope holds some key other than the V1 user key. The upgrade token is unwrapped
    /// with the user key, so a V1 user key leaves no way to recover the other one.
    #[tokio::test]
    async fn migrate_envelope_with_v1_user_key_and_other_key_id_fails() {
        let client = client_with_v1_user_key();

        // Build a V2-sealed envelope using a transient V2 key.
        let v2_envelope = {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let v2_local = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            PasswordProtectedKeyEnvelope::seal(
                v2_local,
                "1234",
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("seal under v2 key")
        };
        assert!(
            v2_envelope.contained_key_id().expect("readable").is_some(),
            "envelope should be V2",
        );

        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&v2_envelope).await;

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::EnvelopeWithKeyIdWithV1UserKey),
        );
    }

    /// The envelope holds the V1 key the upgrade token unwraps.
    #[tokio::test]
    async fn migrate_v1_envelope_with_v2_user_key_reseals_with_user_key() {
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_encrypted_pin(&state.encrypted_pin).await;
        bridge.set_v2_upgrade_token(&state.token).await;

        let user_key_id = user_key_id(&client);
        assert_ne!(
            state.envelope.contained_key_id().expect("readable"),
            Some(user_key_id.clone()),
            "starting envelope holds the V1 key, not the current V2 user key",
        );

        let system = PinLockSystem::with_client(&client);
        system
            .migrate_pin_envelope_if_needed()
            .await
            .expect("migration succeeds");

        let persistent = bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope present after migration");
        let ephemeral = bridge
            .get_ephemeral_pin_envelope()
            .await
            .expect("ephemeral envelope present after migration");
        let encrypted_pin = bridge
            .get_encrypted_pin()
            .await
            .expect("encrypted pin present after migration");

        assert_envelope_wraps_user_key(&client, &persistent, pin, &user_key_id);
        assert_envelope_wraps_user_key(&client, &ephemeral, pin, &user_key_id);
        assert_eq!(decrypt_encrypted_pin(&client, &encrypted_pin), pin);
        assert_eq!(
            system.get_pin_lock_type().await,
            Some(PinLockType::BeforeFirstUnlock),
        );
        assert_eq!(system.get_pin_status().await, PinUnlockStatus::Available);
        assert!(system.unlock(pin).await.is_ok());
    }

    #[tokio::test]
    async fn migrate_v1_envelope_with_v2_user_key_without_token_fails() {
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_encrypted_pin(&state.encrypted_pin).await;
        // Intentionally omit set_v2_upgrade_token.

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::MissingV2UpgradeToken),
        );
    }

    #[tokio::test]
    async fn migrate_v1_envelope_with_v2_user_key_without_encrypted_pin_fails() {
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_v2_upgrade_token(&state.token).await;
        // Intentionally omit set_encrypted_pin.

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::MissingEncryptedPin),
        );
    }

    #[tokio::test]
    async fn migrate_v1_envelope_with_v2_user_key_with_mismatched_token_fails() {
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);

        // Build an unrelated upgrade token from a different (v1, v2) key pair. Its
        // wrapped_user_key_1 is sealed under a V2 key that is *not* in the User slot, so
        // unwrap_v1(SymmetricKeySlotId::User, ..) will fail to decrypt it.
        let unrelated_token = {
            let key_store = bitwarden_crypto::KeyStore::<KeySlotIds>::default();
            let mut ctx = key_store.context_mut();
            let v1 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let v2 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            V2UpgradeToken::create(v1, v2, &ctx).expect("unrelated token created")
        };

        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_encrypted_pin(&state.encrypted_pin).await;
        bridge.set_v2_upgrade_token(&unrelated_token).await;

        let system = PinLockSystem::with_client(&client);
        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::PinDecryption),
        );
    }

    /// The token unwraps, but the envelope holds neither that V1 key nor the current user key, so
    /// the user key was rotated rather than upgraded.
    #[tokio::test]
    async fn migrate_v2_envelope_with_rotated_user_key_fails() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        // Replace the persistent envelope with one sealed under a *different* V2 key, and supply
        // an upgrade token for the current user key so the rotation check is actually reached.
        let (mismatched_envelope, token) = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let other_v2 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            let envelope = PasswordProtectedKeyEnvelope::seal(
                other_v2,
                "1234",
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("seal under other v2 key");

            let v1 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let token = V2UpgradeToken::create(v1, SymmetricKeySlotId::User, &ctx)
                .expect("upgrade token created");
            (envelope, token)
        };

        let bridge = client.km_state_bridge();
        bridge
            .set_persistent_pin_envelope(&mismatched_envelope)
            .await;
        bridge.set_v2_upgrade_token(&token).await;

        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::V2KeyRotationUnsupported),
        );
    }

    /// Without a token the rotation above cannot be distinguished from a V1 envelope, so the
    /// missing token is reported instead.
    #[tokio::test]
    async fn migrate_v2_envelope_with_rotated_user_key_without_token_fails() {
        let client = client_with_user_key();
        let system = PinLockSystem::with_client(&client);
        system
            .set_pin("1234".into(), PinLockType::BeforeFirstUnlock)
            .await
            .expect("set_pin succeeds");

        let mismatched_envelope = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let other_v2 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            PasswordProtectedKeyEnvelope::seal(
                other_v2,
                "1234",
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("seal under other v2 key")
        };
        client
            .km_state_bridge()
            .set_persistent_pin_envelope(&mismatched_envelope)
            .await;

        assert_eq!(
            system.migrate_pin_envelope_if_needed().await,
            Err(MigrationFailed::MissingV2UpgradeToken),
        );
    }

    #[tokio::test]
    async fn on_unlock_triggers_migration() {
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_encrypted_pin(&state.encrypted_pin).await;
        bridge.set_v2_upgrade_token(&state.token).await;

        let user_key_id = user_key_id(&client);
        let system = PinLockSystem::with_client(&client);

        system.on_unlock().await;

        let persistent = bridge
            .get_persistent_pin_envelope()
            .await
            .expect("persistent envelope present after on_unlock");
        assert_envelope_wraps_user_key(&client, &persistent, pin, &user_key_id);
        assert!(system.unlock(pin).await.is_ok());
    }

    #[tokio::test]
    async fn on_unlock_unenrolls_when_migration_fails() {
        // Reuse the missing-upgrade-token scenario to drive migration failure end-to-end.
        let pin = "1234";
        let (client, state) = fresh_v1_state_with_v2_user_key(pin);
        let bridge = client.km_state_bridge();
        bridge.set_persistent_pin_envelope(&state.envelope).await;
        bridge.set_encrypted_pin(&state.encrypted_pin).await;
        // Intentionally omit set_v2_upgrade_token so migration fails.

        let system = PinLockSystem::with_client(&client);
        system.on_unlock().await;

        assert_pin_fully_unenrolled(&client).await;
    }
}
