//! This module contains the definition for the key identifiers used by the rest of the crates.
//! Any code that needs to interact with the [KeyStore] should use these types.
//!
//! - [SymmetricKeySlotId] is used to identify symmetric keys.
//! - [PrivateKeySlotId] is used to identify private keys.
//! - [KeySlotIds] is a helper type that combines both symmetric and private key identifiers. This
//!   is usually used in the type bounds of [KeyStore],
//!   [KeyStoreContext](bitwarden_crypto::KeyStoreContext),
//!   [PrimitiveEncryptable](bitwarden_crypto::PrimitiveEncryptable),
//!   [CompositeEncryptable](bitwarden_crypto::CompositeEncryptable), and
//!   [Decryptable](bitwarden_crypto::Decryptable).

use bitwarden_crypto::{
    EncString, KeyStore, SymmetricCryptoKey, key_slot_ids, safe::PasswordProtectedKeyEnvelope,
};

#[cfg(feature = "internal")]
pub mod account_cryptographic_state;
#[cfg(feature = "internal")]
pub mod crypto;
#[cfg(feature = "internal")]
mod crypto_client;
use bitwarden_encoding::B64;
#[cfg(feature = "internal")]
pub use crypto_client::CryptoClient;

#[cfg(feature = "internal")]
mod master_password;
#[cfg(feature = "internal")]
pub use master_password::{
    MasterPasswordAuthenticationData, MasterPasswordError, MasterPasswordUnlockData,
};
#[cfg(feature = "internal")]
mod security_state;
#[cfg(feature = "internal")]
pub use security_state::{
    MINIMUM_ENFORCE_ICON_URI_HASH_VERSION, SecurityState, SignedSecurityState,
};
#[cfg(feature = "internal")]
mod user_decryption;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "internal")]
pub use user_decryption::UserDecryptionData;
#[cfg(feature = "internal")]
mod v2_upgrade_token;
#[cfg(feature = "internal")]
pub use v2_upgrade_token::{V2UpgradeToken, V2UpgradeTokenError};

#[cfg(all(feature = "internal", feature = "wasm"))]
mod wasm_unlock_state;

#[cfg(feature = "internal")]
mod pin_lock_system;

#[cfg(feature = "internal")]
mod local_user_data_key;
#[cfg(feature = "internal")]
mod local_user_data_key_state;

/// A temporary bridge to access KM-related state from within the SDK.
#[cfg(feature = "internal")]
pub mod state_bridge;

use crate::{OrganizationId, UserId};

/// Represents the decrypted symmetric user-key of a user. This is held in ephemeral state of the
/// client.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(transparent)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct UserKeyState {
    decrypted_user_key: B64,
}

bitwarden_state::register_repository_item!(String => UserKeyState, "UserKey");

/// Represents the local user data key, wrapped by user key.
/// This key is used to encrypt local user data (e.g., password generator history).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalUserDataKeyState {
    wrapped_key: EncString,
}

bitwarden_state::register_repository_item!(UserId => LocalUserDataKeyState, "LocalUserDataKey");

/// Represents the PIN envelope in memory, when ephemeral PIN unlock is used.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EphemeralPinEnvelopeState {
    pin_envelope: PasswordProtectedKeyEnvelope,
}

bitwarden_state::register_repository_item!(String => EphemeralPinEnvelopeState, "EphemeralPinEnvelope");

key_slot_ids! {
    #[symmetric]
    pub enum SymmetricKeySlotId {
        Master,
        User,
        Organization(OrganizationId),
        LocalUserData,
        #[local]
        Local(LocalId),
    }

    #[private]
    pub enum PrivateKeySlotId {
        UserPrivateKey,
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum SigningKeySlotId {
        UserSigningKey,
        #[local]
        Local(LocalId),
    }

    pub KeySlotIds => SymmetricKeySlotId, PrivateKeySlotId, SigningKeySlotId;
}

/// This is a helper function to create a test KeyStore with a single user key.
/// While this function is not marked as #[cfg(test)], it should only be used for testing purposes.
/// It's only public so that other crates can make use of it in their own tests.
pub fn create_test_crypto_with_user_key(key: SymmetricCryptoKey) -> KeyStore<KeySlotIds> {
    let store = KeyStore::default();

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeySlotId::User, key.clone())
        .expect("Mutable context");

    store
}

/// This is a helper function to create a test KeyStore with a single user key and an organization
/// key using the provided organization uuid. While this function is not marked as #[cfg(test)], it
/// should only be used for testing purposes. It's only public so that other crates can make use of
/// it in their own tests.
pub fn create_test_crypto_with_user_and_org_key(
    key: SymmetricCryptoKey,
    org_id: OrganizationId,
    org_key: SymmetricCryptoKey,
) -> KeyStore<KeySlotIds> {
    let store = KeyStore::default();

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeySlotId::User, key.clone())
        .expect("Mutable context");

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeySlotId::Organization(org_id), org_key.clone())
        .expect("Mutable context");

    store
}
