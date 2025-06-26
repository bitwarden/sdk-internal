//! This module contains the definition for the key identifiers used by the rest of the crates.
//! Any code that needs to interact with the [KeyStore] should use these types.
//!
//! - [SymmetricKeyId] is used to identify symmetric keys.
//! - [AsymmetricKeyId] is used to identify asymmetric keys.
//! - [KeyIds] is a helper type that combines both symmetric and asymmetric key identifiers. This is
//!   usually used in the type bounds of [KeyStore],
//!   [KeyStoreContext](bitwarden_crypto::KeyStoreContext),
//!   [Encryptable](bitwarden_crypto::Encryptable) and [Decryptable](bitwarden_crypto::Encryptable).
use bitwarden_crypto::{key_ids, KeyStore, SymmetricCryptoKey};

#[cfg(feature = "internal")]
pub mod crypto;
#[cfg(feature = "internal")]
mod crypto_client;
#[cfg(feature = "internal")]
pub use crypto_client::CryptoClient;

key_ids! {
    #[symmetric]
    pub enum SymmetricKeyId {
        Master,
        User,
        Organization(uuid::Uuid),
        #[local]
        Local(&'static str),
    }

    #[asymmetric]
    pub enum AsymmetricKeyId {
        UserPrivateKey,
        #[local]
        Local(&'static str),
    }

    #[signing]
    pub enum SigningKeyId {
        UserSigningKey,
        #[local]
        Local(&'static str),
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
    org_id: uuid::Uuid,
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
