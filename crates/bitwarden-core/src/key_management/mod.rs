//! This module contains the definition for the key identifiers used by the rest of the crates.
//! Any code that needs to interact with the [KeyStore] should use these types.
//!
//! - [SymmetricKeyId] is used to identify symmetric keys.
//! - [AsymmetricKeyId] is used to identify asymmetric keys.
//! - [KeyIds] is a helper type that combines both symmetric and asymmetric key identifiers. This is
//!   usually used in the type bounds of [KeyStore],
//!   [KeyStoreContext](bitwarden_crypto::KeyStoreContext),
//!   [PrimitiveEncryptable](bitwarden_crypto::PrimitiveEncryptable),
//!   [CompositeEncryptable](bitwarden_crypto::CompositeEncryptable), and
//!   [Decryptable](bitwarden_crypto::Decryptable).

use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, key_ids};

#[cfg(feature = "internal")]
pub mod account_cryptographic_state;
#[cfg(feature = "internal")]
pub mod crypto;
#[cfg(feature = "internal")]
mod crypto_client;
#[cfg(feature = "internal")]
pub use crypto_client::CryptoClient;

#[cfg(feature = "internal")]
mod master_password;
#[cfg(feature = "internal")]
pub use master_password::MasterPasswordError;
#[cfg(feature = "internal")]
pub(crate) use master_password::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
#[cfg(feature = "internal")]
mod security_state;
#[cfg(feature = "internal")]
pub use security_state::{
    MINIMUM_ENFORCE_ICON_URI_HASH_VERSION, SecurityState, SignedSecurityState,
};
#[cfg(feature = "internal")]
mod user_decryption;
#[cfg(feature = "internal")]
pub use user_decryption::UserDecryptionData;

use crate::OrganizationId;

key_ids! {
    #[symmetric]
    pub enum SymmetricKeyId {
        Master,
        User,
        Organization(OrganizationId),
        #[local]
        Local(LocalId),
    }

    #[asymmetric]
    pub enum AsymmetricKeyId {
        UserPrivateKey,
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum SigningKeyId {
        UserSigningKey,
        #[local]
        Local(LocalId),
    }

    pub KeyIds => SymmetricKeyId, AsymmetricKeyId, SigningKeyId;
}

/// This is a helper function to create a test KeyStore with a single user key.
/// While this function is not marked as #[cfg(test)], it should only be used for testing purposes.
/// It's only public so that other crates can make use of it in their own tests.
pub fn create_test_crypto_with_user_key(key: SymmetricCryptoKey) -> KeyStore<KeyIds> {
    let store = KeyStore::default();

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeyId::User, key.clone())
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
) -> KeyStore<KeyIds> {
    let store = KeyStore::default();

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeyId::User, key.clone())
        .expect("Mutable context");

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeyId::Organization(org_id), org_key.clone())
        .expect("Mutable context");

    store
}
