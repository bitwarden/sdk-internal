use bitwarden_crypto::{key_ids, KeyStore, SymmetricCryptoKey};

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

    pub KeyIds => SymmetricKeyId, AsymmetricKeyId;
}

pub fn create_test_crypto_with_user_key(key: SymmetricCryptoKey) -> KeyStore<KeyIds> {
    let store = KeyStore::default();

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(SymmetricKeyId::User, key.clone())
        .expect("Mutable context");

    store
}

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
