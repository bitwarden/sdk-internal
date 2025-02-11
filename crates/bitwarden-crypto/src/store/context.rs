use std::{
    cell::Cell,
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use rsa::Oaep;
use zeroize::{Zeroize, Zeroizing};

use super::KeyStoreInner;
use crate::{
    derive_shareable_key, store::backend::StoreBackend, AsymmetricCryptoKey, AsymmetricEncString,
    CryptoError, CryptoKey, Decryptable, EncString, Encryptable, KeyId, KeyIds, Result,
    SymmetricCryptoKey,
};

/// The context of a crypto operation using [super::KeyStore]
///
/// This will usually be accessed from an implementation of [crate::Decryptable] or
/// [crate::Encryptable], but can also be obtained through [super::KeyStore::context]
///
/// This context contains access to the user keys stored in the [super::KeyStore] (sometimes
/// referred to as `global keys`) and it also contains it's own individual secure backend for key
/// storage. Keys stored in this individual backend are usually referred to as `local keys`, they
/// will be cleared when this context goes out of scope and is dropped and they do not affect either
/// the global [super::KeyStore] or other instances of contexts.
///
/// This context-local storage is recommended for ephemeral and temporary keys that are decrypted
/// during the course of a decrypt/encrypt operation, but won't be used after the operation itself
/// is complete.
///
/// ```rust
/// # use bitwarden_crypto::*;
/// # key_ids! {
/// #     #[symmetric]
/// #     pub enum SymmKeyId {
/// #         User,
/// #         Local(&'static str),
/// #     }
/// #     #[asymmetric]
/// #     pub enum AsymmKeyId {
/// #         UserPrivate,
/// #     }
/// #     pub Ids => SymmKeyId, AsymmKeyId;
/// # }
/// struct Data {
///     key: EncString,
///     name: String,
/// }
/// # impl IdentifyKey<SymmKeyId> for Data {
/// #    fn key_identifier(&self) -> SymmKeyId {
/// #        SymmKeyId::User
/// #    }
/// # }
///
/// const LOCAL_KEY: SymmKeyId = SymmKeyId::Local("local_key_id");
///
/// impl Encryptable<Ids, SymmKeyId, EncString> for Data {
///     fn encrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeyId) -> Result<EncString, CryptoError> {
///         let local_key_id = ctx.decrypt_key_into_store(key, LOCAL_KEY, &self.key)?;
///         self.name.encrypt(ctx, local_key_id)
///     }
/// }
/// ```
#[must_use]
pub struct KeyStoreContext<'a, Ids: KeyIds> {
    pub(super) global_keys: GlobalKeys<'a, Ids>,

    pub(super) local_symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    pub(super) local_asymmetric_keys: Box<dyn StoreBackend<Ids::Asymmetric>>,

    // Make sure the context is !Send & !Sync
    pub(super) _phantom: std::marker::PhantomData<(Cell<()>, RwLockReadGuard<'static, ()>)>,
}

/// A KeyStoreContext is usually limited to a read only access to the global keys,
/// which allows us to have multiple read only contexts at the same time and do multitheaded
/// encryption/decryption. We also have the option to create a read/write context, which allows us
/// to modify the global keys, but only allows one context at a time. This is controlled by a
/// [std::sync::RwLock] on the global keys, and this struct stores both types of guards.
pub(crate) enum GlobalKeys<'a, Ids: KeyIds> {
    ReadOnly(RwLockReadGuard<'a, KeyStoreInner<Ids>>),
    ReadWrite(RwLockWriteGuard<'a, KeyStoreInner<Ids>>),
}

impl<Ids: KeyIds> GlobalKeys<'_, Ids> {
    pub fn get(&self) -> &KeyStoreInner<Ids> {
        match self {
            GlobalKeys::ReadOnly(keys) => keys,
            GlobalKeys::ReadWrite(keys) => keys,
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut KeyStoreInner<Ids>> {
        match self {
            GlobalKeys::ReadOnly(_) => Err(CryptoError::ReadOnlyKeyStore),
            GlobalKeys::ReadWrite(keys) => Ok(keys),
        }
    }
}

// TODO: We should probably unify how we handle key parsing, and implement TryFrom<Vec<u8>> and
// TryInto<Vec<u8>> for all keys
pub trait KeyBytes: Sized {
    fn as_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
impl KeyBytes for SymmetricCryptoKey {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SymmetricCryptoKey::try_from(bytes.to_vec())
    }
}
impl KeyBytes for AsymmetricCryptoKey {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.to_der()?.as_slice().to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        AsymmetricCryptoKey::from_der(bytes)
    }
}

mod internal {
    use super::*;
    pub trait ContextHasKeys<Id: KeyId<KeyValue = Key>, Key: CryptoKey, ContextIds: KeyIds> {
        fn internal_get_key(&self, id: Id) -> Result<&Id::KeyValue>;
        fn internal_set_key(&mut self, id: Id, value: Id::KeyValue) -> Result<()>;
    }
}
use internal::ContextHasKeys;

impl<ContextIds: KeyIds> ContextHasKeys<ContextIds::Symmetric, SymmetricCryptoKey, ContextIds>
    for KeyStoreContext<'_, ContextIds>
{
    fn internal_get_key(&self, id: ContextIds::Symmetric) -> Result<&SymmetricCryptoKey> {
        if id.is_local() {
            self.local_symmetric_keys.get(id)
        } else {
            self.global_keys.get().symmetric_keys.get(id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{id:?}")))
    }

    fn internal_set_key(
        &mut self,
        id: ContextIds::Symmetric,
        value: SymmetricCryptoKey,
    ) -> Result<()> {
        if id.is_local() {
            self.local_symmetric_keys.upsert(id, value);
        } else {
            self.global_keys.get_mut()?.symmetric_keys.upsert(id, value);
        }
        Ok(())
    }
}

impl<ContextIds: KeyIds> ContextHasKeys<ContextIds::Asymmetric, AsymmetricCryptoKey, ContextIds>
    for KeyStoreContext<'_, ContextIds>
{
    fn internal_get_key(&self, id: ContextIds::Asymmetric) -> Result<&AsymmetricCryptoKey> {
        if id.is_local() {
            self.local_asymmetric_keys.get(id)
        } else {
            self.global_keys.get().asymmetric_keys.get(id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{id:?}")))
    }

    fn internal_set_key(
        &mut self,
        id: ContextIds::Asymmetric,
        value: AsymmetricCryptoKey,
    ) -> Result<()> {
        if id.is_local() {
            self.local_asymmetric_keys.upsert(id, value);
        } else {
            self.global_keys
                .get_mut()?
                .asymmetric_keys
                .upsert(id, value);
        }
        Ok(())
    }
}

impl<Ids: KeyIds> KeyStoreContext<'_, Ids> {
    /// Clears all the local keys stored in this context
    /// This will not affect the global keys even if this context has write access.
    /// To clear the global keys, you need to use [super::KeyStore::clear] instead.
    pub fn clear_local(&mut self) {
        self.local_symmetric_keys.clear();
        self.local_asymmetric_keys.clear();
    }

    /// Remove all symmetric keys from the context for which the predicate returns false
    /// This will also remove the keys from the global store if this context has write access
    pub fn retain_symmetric_keys(&mut self, f: fn(Ids::Symmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.symmetric_keys.retain(f);
        }
        self.local_symmetric_keys.retain(f);
    }

    /// Remove all asymmetric keys from the context for which the predicate returns false
    /// This will also remove the keys from the global store if this context has write access
    pub fn retain_asymmetric_keys(&mut self, f: fn(Ids::Asymmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.asymmetric_keys.retain(f);
        }
        self.local_asymmetric_keys.retain(f);
    }

    /// Decrypt a key into the context by using an already existing key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to decrypt the `encrypted_key`. It must already exist
    ///   in the context
    /// * `decrypted_key_id` - The key id where the decrypted key will be stored. If it already
    ///   exists, it will be overwritten
    /// * `encrypted_key` - The key to decrypt
    pub fn decrypt_key_into_store<EncryptedKey, EncryptionKeyId, DecryptedKeyId>(
        &mut self,
        encryption_key: EncryptionKeyId,
        decrypted_key_id: DecryptedKeyId,
        encrypted_key: &EncryptedKey,
    ) -> Result<DecryptedKeyId>
    where
        Self: ContextHasKeys<DecryptedKeyId, DecryptedKeyId::KeyValue, Ids>,
        EncryptedKey: Decryptable<Ids, EncryptionKeyId, Vec<u8>>,
        DecryptedKeyId: KeyId,
        DecryptedKeyId::KeyValue: KeyBytes,
        EncryptionKeyId: KeyId,
    {
        let decrypted_key = encrypted_key.decrypt(self, encryption_key)?;
        let decrypted_key: DecryptedKeyId::KeyValue = KeyBytes::from_bytes(&decrypted_key)?;

        self.internal_set_key(decrypted_key_id, decrypted_key)?;
        Ok(decrypted_key_id)
    }

    /// Encrypt and return a symmetric key from the context by using an already existing symmetric
    /// key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to encrypt the `key_to_encrypt`. It must already exist
    ///   in the context
    /// * `key_to_encrypt` - The key id to encrypt. It must already exist in the context
    pub fn encrypt_key_from_store<DecryptedKeyId, EncryptionKeyId, EncryptedKey>(
        &mut self,
        encryption_key: EncryptionKeyId,
        key_to_encrypt: DecryptedKeyId,
    ) -> Result<EncryptedKey>
    where
        Self: ContextHasKeys<DecryptedKeyId, DecryptedKeyId::KeyValue, Ids>,
        EncryptionKeyId: KeyId,
        DecryptedKeyId: KeyId,
        DecryptedKeyId::KeyValue: KeyBytes,
        for<'a> &'a [u8]: Encryptable<Ids, EncryptionKeyId, EncryptedKey>,
    {
        let key_to_encrypt: &DecryptedKeyId::KeyValue = self.internal_get_key(key_to_encrypt)?;

        let mut key_bytes = key_to_encrypt.as_bytes()?;
        let encrypted_key = key_bytes.as_slice().encrypt(self, encryption_key)?;

        key_bytes.zeroize();

        Ok(encrypted_key)
    }

    /// Returns `true` if the context has a key with the given identifier
    pub fn has_key<Id: KeyId>(&self, key_id: Id) -> bool
    where
        Self: ContextHasKeys<Id, Id::KeyValue, Ids>,
    {
        self.internal_get_key(key_id).is_ok()
    }

    /// Generate a new random symmetric key and store it in the context
    pub fn generate_symmetric_key(&mut self, key_id: Ids::Symmetric) -> Result<Ids::Symmetric> {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        self.internal_set_key(key_id, key)?;
        Ok(key_id)
    }

    /// Derive a shareable key using hkdf from secret and name and store it in the context.
    ///
    /// A specialized variant of this function was called `CryptoService.makeSendKey` in the
    /// Bitwarden `clients` repository.
    pub fn derive_shareable_key(
        &mut self,
        key_id: Ids::Symmetric,
        secret: Zeroizing<[u8; 16]>,
        name: &str,
        info: Option<&str>,
    ) -> Result<Ids::Symmetric> {
        self.internal_set_key(key_id, derive_shareable_key(secret, name, info))?;
        Ok(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn dangerous_get_key<Id: KeyId>(&self, key_id: Id) -> Result<&Id::KeyValue>
    where
        Self: ContextHasKeys<Id, Id::KeyValue, Ids>,
    {
        self.internal_get_key(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_key<Id: KeyId>(&mut self, key_id: Id, key_value: Id::KeyValue) -> Result<()>
    where
        Self: ContextHasKeys<Id, Id::KeyValue, Ids>,
    {
        self.internal_set_key(key_id, key_value)
    }

    pub(crate) fn decrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &EncString,
    ) -> Result<Vec<u8>> {
        let key = self.internal_get_key(key)?;

        match data {
            EncString::AesCbc256_B64 { iv, data } => {
                let dec = crate::aes::decrypt_aes256(iv, data.clone(), &key.key)?;
                Ok(dec)
            }
            EncString::AesCbc256_HmacSha256_B64 { iv, mac, data } => {
                let mac_key = key.mac_key.as_ref().ok_or(CryptoError::InvalidMac)?;
                let dec =
                    crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), mac_key, &key.key)?;
                Ok(dec)
            }
        }
    }

    pub(crate) fn encrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &[u8],
    ) -> Result<EncString> {
        let key = self.internal_get_key(key)?;
        EncString::encrypt_aes256_hmac(
            data,
            key.mac_key.as_ref().ok_or(CryptoError::InvalidMac)?,
            &key.key,
        )
    }

    pub(crate) fn decrypt_data_with_asymmetric_key(
        &self,
        key: Ids::Asymmetric,
        data: &AsymmetricEncString,
    ) -> Result<Vec<u8>> {
        let key = self.internal_get_key(key)?;

        use AsymmetricEncString::*;
        match data {
            Rsa2048_OaepSha256_B64 { data } => key.key.decrypt(Oaep::new::<sha2::Sha256>(), data),
            Rsa2048_OaepSha1_B64 { data } => key.key.decrypt(Oaep::new::<sha1::Sha1>(), data),
            #[allow(deprecated)]
            Rsa2048_OaepSha256_HmacSha256_B64 { data, .. } => {
                key.key.decrypt(Oaep::new::<sha2::Sha256>(), data)
            }
            #[allow(deprecated)]
            Rsa2048_OaepSha1_HmacSha256_B64 { data, .. } => {
                key.key.decrypt(Oaep::new::<sha1::Sha1>(), data)
            }
        }
        .map_err(|_| CryptoError::KeyDecrypt)
    }

    pub(crate) fn encrypt_data_with_asymmetric_key(
        &self,
        key: Ids::Asymmetric,
        data: &[u8],
    ) -> Result<AsymmetricEncString> {
        let key = self.internal_get_key(key)?;
        AsymmetricEncString::encrypt_rsa2048_oaep_sha1(data, key)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::{
        store::{tests::DataView, KeyStore},
        traits::tests::{TestIds, TestSymmKey},
        Decryptable, Encryptable, SymmetricCryptoKey,
    };

    #[test]
    fn test_set_keys_for_encryption() {
        let mut rng = rand::thread_rng();
        let store: KeyStore<TestIds> = KeyStore::default();

        // Generate and insert a key
        let key_a0_id = TestSymmKey::A(0);
        let key_a0 = SymmetricCryptoKey::generate(&mut rng);

        store
            .context_mut()
            .set_key(TestSymmKey::A(0), key_a0.clone())
            .unwrap();

        assert!(store.context().has_key(key_a0_id));

        // Encrypt some data with the key
        let data = DataView("Hello, World!".to_string(), key_a0_id);
        let _encrypted = data.encrypt(&mut store.context(), key_a0_id).unwrap();
    }

    #[test]
    fn test_key_encryption() {
        let mut rng = rand::thread_rng();
        let store: KeyStore<TestIds> = KeyStore::default();

        let mut ctx = store.context();

        // Generate and insert a key
        let key_1_id = TestSymmKey::C(1);
        let key_1 = SymmetricCryptoKey::generate(&mut rng);

        ctx.set_key(key_1_id, key_1.clone()).unwrap();

        assert!(ctx.has_key(key_1_id));

        // Generate and insert a new key
        let key_2_id = TestSymmKey::C(2);
        let key_2 = SymmetricCryptoKey::generate(&mut rng);

        ctx.set_key(key_2_id, key_2.clone()).unwrap();

        assert!(ctx.has_key(key_2_id));

        // Encrypt the new key with the old key
        let key_2_enc = ctx.encrypt_key_from_store(key_1_id, key_2_id).unwrap();

        // Decrypt the new key with the old key in a different identifier
        let new_key_id = TestSymmKey::C(3);

        ctx.decrypt_key_into_store(key_1_id, new_key_id, &key_2_enc)
            .unwrap();

        // Now `key_2_id` and `new_key_id` contain the same key, so we should be able to encrypt
        // with one and decrypt with the other

        let data = DataView("Hello, World!".to_string(), key_2_id);
        let encrypted = data.encrypt(&mut ctx, key_2_id).unwrap();

        let decrypted1 = encrypted.decrypt(&mut ctx, key_2_id).unwrap();
        let decrypted2 = encrypted.decrypt(&mut ctx, new_key_id).unwrap();

        // Assert that the decrypted data is the same
        assert_eq!(decrypted1.0, decrypted2.0);
    }
}
