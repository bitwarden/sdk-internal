use std::{
    cell::Cell,
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use serde::Serialize;
use zeroize::Zeroizing;

use super::KeyStoreInner;
use crate::{
    AsymmetricCryptoKey, BitwardenLegacyKeyBytes, ContentFormat, CryptoError, EncString, KeyId,
    KeyIds, PublicKeyEncryptionAlgorithm, Result, RotatedUserKeys, Signature, SignatureAlgorithm,
    SignedObject, SignedPublicKey, SignedPublicKeyMessage, SigningKey, SymmetricCryptoKey,
    UnsignedSharedKey, derive_shareable_key, error::UnsupportedOperationError, signing,
    store::backend::StoreBackend,
};

/// The context of a crypto operation using [super::KeyStore]
///
/// This will usually be accessed from an implementation of [crate::Decryptable] or
/// [crate::CompositeEncryptable], [crate::PrimitiveEncryptable],
/// but can also be obtained
/// through [super::KeyStore::context]
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
/// #     #[signing]
/// #     pub enum SigningKeyId {
/// #         UserSigning,
/// #     }
/// #     pub Ids => SymmKeyId, AsymmKeyId, SigningKeyId;
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
/// impl CompositeEncryptable<Ids, SymmKeyId, EncString> for Data {
///     fn encrypt_composite(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeyId) -> Result<EncString, CryptoError> {
///         let local_key_id = ctx.unwrap_symmetric_key(key, LOCAL_KEY, &self.key)?;
///         self.name.encrypt(ctx, local_key_id)
///     }
/// }
/// ```
#[must_use]
pub struct KeyStoreContext<'a, Ids: KeyIds> {
    pub(super) global_keys: GlobalKeys<'a, Ids>,

    pub(super) local_symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    pub(super) local_asymmetric_keys: Box<dyn StoreBackend<Ids::Asymmetric>>,
    pub(super) local_signing_keys: Box<dyn StoreBackend<Ids::Signing>>,

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

impl<Ids: KeyIds> KeyStoreContext<'_, Ids> {
    /// Clears all the local keys stored in this context
    /// This will not affect the global keys even if this context has write access.
    /// To clear the global keys, you need to use [super::KeyStore::clear] instead.
    pub fn clear_local(&mut self) {
        self.local_symmetric_keys.clear();
        self.local_asymmetric_keys.clear();
        self.local_signing_keys.clear();
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

    // TODO: All these encrypt x key with x key look like they need to be made generic,
    // but I haven't found the best way to do that yet.

    /// Decrypt a symmetric key into the context by using an already existing symmetric key
    ///
    /// # Arguments
    ///
    /// * `wrapping_key` - The key id used to decrypt the `wrapped_key`. It must already exist in
    ///   the context
    /// * `new_key_id` - The key id where the decrypted key will be stored. If it already exists, it
    ///   will be overwritten
    /// * `wrapped_key` - The key to decrypt
    pub fn unwrap_symmetric_key(
        &mut self,
        wrapping_key: Ids::Symmetric,
        new_key_id: Ids::Symmetric,
        wrapped_key: &EncString,
    ) -> Result<Ids::Symmetric> {
        let wrapping_key = self.get_symmetric_key(wrapping_key)?;

        let key = match (wrapped_key, wrapping_key) {
            (EncString::Aes256Cbc_B64 { iv, data }, SymmetricCryptoKey::Aes256CbcKey(key)) => {
                SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(
                    crate::aes::decrypt_aes256(iv, data.clone(), &key.enc_key)?,
                ))?
            }
            (
                EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data },
                SymmetricCryptoKey::Aes256CbcHmacKey(key),
            ) => SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(
                crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), &key.mac_key, &key.enc_key)?,
            ))?,
            (
                EncString::Cose_Encrypt0_B64 { data },
                SymmetricCryptoKey::XChaCha20Poly1305Key(key),
            ) => {
                let (content_bytes, content_format) =
                    crate::cose::decrypt_xchacha20_poly1305(data, key)?;
                match content_format {
                    ContentFormat::BitwardenLegacyKey => {
                        SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(content_bytes))?
                    }
                    ContentFormat::CoseKey => SymmetricCryptoKey::try_from_cose(&content_bytes)?,
                    _ => return Err(CryptoError::InvalidKey),
                }
            }
            _ => return Err(CryptoError::InvalidKey),
        };

        #[allow(deprecated)]
        self.set_symmetric_key(new_key_id, key)?;

        // Returning the new key identifier for convenience
        Ok(new_key_id)
    }

    /// Encrypt and return a symmetric key from the context by using an already existing symmetric
    /// key
    ///
    /// # Arguments
    ///
    /// * `wrapping_key` - The key id used to wrap (encrypt) the `key_to_wrap`. It must already
    ///   exist in the context
    /// * `key_to_wrap` - The key id to wrap. It must already exist in the context
    pub fn wrap_symmetric_key(
        &self,
        wrapping_key: Ids::Symmetric,
        key_to_wrap: Ids::Symmetric,
    ) -> Result<EncString> {
        use SymmetricCryptoKey::*;

        let wrapping_key_instance = self.get_symmetric_key(wrapping_key)?;
        let key_to_wrap_instance = self.get_symmetric_key(key_to_wrap)?;
        // `Aes256CbcHmacKey` can wrap keys by encrypting their byte serialization obtained using
        // `SymmetricCryptoKey::to_encoded()`. `XChaCha20Poly1305Key` need to specify the
        // content format to be either octet stream, in case the wrapped key is a Aes256CbcHmacKey
        // or `Aes256CbcKey`, or by specifying the content format to be CoseKey, in case the
        // wrapped key is a `XChaCha20Poly1305Key`.
        match (wrapping_key_instance, key_to_wrap_instance) {
            (
                Aes256CbcHmacKey(_),
                Aes256CbcHmacKey(_) | Aes256CbcKey(_) | XChaCha20Poly1305Key(_),
            ) => self.encrypt_data_with_symmetric_key(
                wrapping_key,
                key_to_wrap_instance
                    .to_encoded()
                    .as_ref()
                    .to_vec()
                    .as_slice(),
                ContentFormat::BitwardenLegacyKey,
            ),
            (XChaCha20Poly1305Key(_), _) => {
                let encoded = key_to_wrap_instance.to_encoded_raw();
                let content_format = encoded.content_format();
                self.encrypt_data_with_symmetric_key(
                    wrapping_key,
                    Into::<Vec<u8>>::into(encoded).as_slice(),
                    content_format,
                )
            }
            _ => Err(CryptoError::OperationNotSupported(
                UnsupportedOperationError::EncryptionNotImplementedForKey,
            )),
        }
    }

    /// Decapsulate a symmetric key into the context by using an already existing asymmetric key
    ///
    /// # Arguments
    ///
    /// * `decapsulation_key` - The key id used to decrypt the `encrypted_key`. It must already
    ///   exist in the context
    /// * `new_key_id` - The key id where the decrypted key will be stored. If it already exists, it
    ///   will be overwritten
    /// * `encapsulated_shared_key` - The symmetric key to decrypt
    pub fn decapsulate_key_unsigned(
        &mut self,
        decapsulation_key: Ids::Asymmetric,
        new_key_id: Ids::Symmetric,
        encapsulated_shared_key: &UnsignedSharedKey,
    ) -> Result<Ids::Symmetric> {
        let decapsulation_key = self.get_asymmetric_key(decapsulation_key)?;
        let decapsulated_key =
            encapsulated_shared_key.decapsulate_key_unsigned(decapsulation_key)?;

        #[allow(deprecated)]
        self.set_symmetric_key(new_key_id, decapsulated_key)?;

        // Returning the new key identifier for convenience
        Ok(new_key_id)
    }

    /// Encapsulate and return a symmetric key from the context by using an already existing
    /// asymmetric key
    ///
    /// # Arguments
    ///
    /// * `encapsulation_key` - The key id used to encrypt the `encapsulated_key`. It must already
    ///   exist in the context
    /// * `shared_key` - The key id to encrypt. It must already exist in the context
    pub fn encapsulate_key_unsigned(
        &self,
        encapsulation_key: Ids::Asymmetric,
        shared_key: Ids::Symmetric,
    ) -> Result<UnsignedSharedKey> {
        UnsignedSharedKey::encapsulate_key_unsigned(
            self.get_symmetric_key(shared_key)?,
            &self.get_asymmetric_key(encapsulation_key)?.to_public_key(),
        )
    }

    /// Returns `true` if the context has a symmetric key with the given identifier
    pub fn has_symmetric_key(&self, key_id: Ids::Symmetric) -> bool {
        self.get_symmetric_key(key_id).is_ok()
    }

    /// Returns `true` if the context has an asymmetric key with the given identifier
    pub fn has_asymmetric_key(&self, key_id: Ids::Asymmetric) -> bool {
        self.get_asymmetric_key(key_id).is_ok()
    }

    /// Returns `true` if the context has a signing key with the given identifier
    pub fn has_signing_key(&self, key_id: Ids::Signing) -> bool {
        self.get_signing_key(key_id).is_ok()
    }

    /// Generate a new random symmetric key and store it in the context
    pub fn generate_symmetric_key(&mut self, key_id: Ids::Symmetric) -> Result<Ids::Symmetric> {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        #[allow(deprecated)]
        self.set_symmetric_key(key_id, key)?;
        Ok(key_id)
    }

    /// Generate a new random xchacha20-poly1305 symmetric key and store it in the context
    #[cfg(test)]
    pub(crate) fn make_cose_symmetric_key(
        &mut self,
        key_id: Ids::Symmetric,
    ) -> Result<Ids::Symmetric> {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        #[allow(deprecated)]
        self.set_symmetric_key(key_id, key)?;
        Ok(key_id)
    }

    /// Makes a new asymmetric encryption key using the current default algorithm, and stores it in
    /// the context
    pub fn make_asymmetric_key(&mut self, key_id: Ids::Asymmetric) -> Result<Ids::Asymmetric> {
        let key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        #[allow(deprecated)]
        self.set_asymmetric_key(key_id, key)?;
        Ok(key_id)
    }

    /// Generate a new signature key using the current default algorithm, and store it in the
    /// context
    pub fn make_signing_key(&mut self, key_id: Ids::Signing) -> Result<Ids::Signing> {
        let key = SigningKey::make(SignatureAlgorithm::default_algorithm());
        #[allow(deprecated)]
        self.set_signing_key(key_id, key)?;
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
        #[allow(deprecated)]
        self.set_symmetric_key(
            key_id,
            SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(secret, name, info)),
        )?;
        Ok(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    #[allow(missing_docs)]
    pub fn dangerous_get_symmetric_key(
        &self,
        key_id: Ids::Symmetric,
    ) -> Result<&SymmetricCryptoKey> {
        self.get_symmetric_key(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    #[allow(missing_docs)]
    pub fn dangerous_get_asymmetric_key(
        &self,
        key_id: Ids::Asymmetric,
    ) -> Result<&AsymmetricCryptoKey> {
        self.get_asymmetric_key(key_id)
    }

    /// Makes a signed public key from an asymmetric private key and signing key stored in context.
    /// Signing a public key asserts ownership, and makes the claim to other users that if they want
    /// to share with you, they can use this public key.
    pub fn make_signed_public_key(
        &self,
        private_key_id: Ids::Asymmetric,
        signing_key_id: Ids::Signing,
    ) -> Result<SignedPublicKey> {
        let public_key = self.get_asymmetric_key(private_key_id)?.to_public_key();
        let signing_key = self.get_signing_key(signing_key_id)?;
        let signed_public_key =
            SignedPublicKeyMessage::from_public_key(&public_key)?.sign(signing_key)?;
        Ok(signed_public_key)
    }

    fn get_symmetric_key(&self, key_id: Ids::Symmetric) -> Result<&SymmetricCryptoKey> {
        if key_id.is_local() {
            self.local_symmetric_keys.get(key_id)
        } else {
            self.global_keys.get().symmetric_keys.get(key_id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{key_id:?}")))
    }

    pub(super) fn get_asymmetric_key(
        &self,
        key_id: Ids::Asymmetric,
    ) -> Result<&AsymmetricCryptoKey> {
        if key_id.is_local() {
            self.local_asymmetric_keys.get(key_id)
        } else {
            self.global_keys.get().asymmetric_keys.get(key_id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{key_id:?}")))
    }

    pub(super) fn get_signing_key(&self, key_id: Ids::Signing) -> Result<&SigningKey> {
        if key_id.is_local() {
            self.local_signing_keys.get(key_id)
        } else {
            self.global_keys.get().signing_keys.get(key_id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{key_id:?}")))
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    #[allow(missing_docs)]
    pub fn set_symmetric_key(
        &mut self,
        key_id: Ids::Symmetric,
        key: SymmetricCryptoKey,
    ) -> Result<()> {
        if key_id.is_local() {
            self.local_symmetric_keys.upsert(key_id, key);
        } else {
            self.global_keys
                .get_mut()?
                .symmetric_keys
                .upsert(key_id, key);
        }
        Ok(())
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    #[allow(missing_docs)]
    pub fn set_asymmetric_key(
        &mut self,
        key_id: Ids::Asymmetric,
        key: AsymmetricCryptoKey,
    ) -> Result<()> {
        if key_id.is_local() {
            self.local_asymmetric_keys.upsert(key_id, key);
        } else {
            self.global_keys
                .get_mut()?
                .asymmetric_keys
                .upsert(key_id, key);
        }
        Ok(())
    }

    /// Sets a signing key in the context
    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_signing_key(&mut self, key_id: Ids::Signing, key: SigningKey) -> Result<()> {
        if key_id.is_local() {
            self.local_signing_keys.upsert(key_id, key);
        } else {
            self.global_keys.get_mut()?.signing_keys.upsert(key_id, key);
        }
        Ok(())
    }

    pub(crate) fn decrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &EncString,
    ) -> Result<Vec<u8>> {
        let key = self.get_symmetric_key(key)?;

        match (data, key) {
            (EncString::Aes256Cbc_B64 { iv, data }, SymmetricCryptoKey::Aes256CbcKey(key)) => {
                crate::aes::decrypt_aes256(iv, data.clone(), &key.enc_key)
            }
            (
                EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data },
                SymmetricCryptoKey::Aes256CbcHmacKey(key),
            ) => crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), &key.mac_key, &key.enc_key),
            (
                EncString::Cose_Encrypt0_B64 { data },
                SymmetricCryptoKey::XChaCha20Poly1305Key(key),
            ) => {
                let (data, _) = crate::cose::decrypt_xchacha20_poly1305(data, key)?;
                Ok(data)
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub(crate) fn encrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &[u8],
        content_format: ContentFormat,
    ) -> Result<EncString> {
        let key = self.get_symmetric_key(key)?;
        match key {
            SymmetricCryptoKey::Aes256CbcKey(_) => Err(CryptoError::OperationNotSupported(
                UnsupportedOperationError::EncryptionNotImplementedForKey,
            )),
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => EncString::encrypt_aes256_hmac(data, key),
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => {
                EncString::encrypt_xchacha20_poly1305(data, key, content_format)
            }
        }
    }

    /// Signs the given data using the specified signing key, for the given
    /// [crate::SigningNamespace] and returns the signature and the serialized message. See
    /// [crate::SigningKey::sign]
    pub fn sign<Message: Serialize>(
        &self,
        key: Ids::Signing,
        message: &Message,
        namespace: &crate::SigningNamespace,
    ) -> Result<SignedObject> {
        self.get_signing_key(key)?.sign(message, namespace)
    }

    /// Signs the given data using the specified signing key, for the given
    /// [crate::SigningNamespace] and returns the signature and the serialized message. See
    /// [crate::SigningKey::sign_detached]
    #[allow(unused)]
    pub(crate) fn sign_detached<Message: Serialize>(
        &self,
        key: Ids::Signing,
        message: &Message,
        namespace: &crate::SigningNamespace,
    ) -> Result<(Signature, signing::SerializedMessage)> {
        self.get_signing_key(key)?.sign_detached(message, namespace)
    }

    /// Re-encrypts the user's keys with the provided symmetric key for a v2 user.
    pub fn dangerous_get_v2_rotated_account_keys(
        &self,
        current_user_private_key_id: Ids::Asymmetric,
        current_user_signing_key_id: Ids::Signing,
    ) -> Result<RotatedUserKeys> {
        crate::dangerous_get_v2_rotated_account_keys(
            current_user_private_key_id,
            current_user_signing_key_id,
            self,
        )
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{
        AsymmetricCryptoKey, AsymmetricPublicCryptoKey, CompositeEncryptable, CoseKeyBytes,
        CoseSerializable, CryptoError, Decryptable, KeyDecryptable, Pkcs8PrivateKeyBytes,
        PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SigningKey, SigningNamespace,
        SymmetricCryptoKey,
        store::{
            KeyStore,
            tests::{Data, DataView},
        },
        traits::tests::{TestAsymmKey, TestIds, TestSigningKey, TestSymmKey},
    };

    #[test]
    fn test_set_signing_key() {
        let store: KeyStore<TestIds> = KeyStore::default();

        // Generate and insert a key
        let key_a0_id = TestSigningKey::A(0);
        let key_a0 = SigningKey::make(SignatureAlgorithm::Ed25519);
        store
            .context_mut()
            .set_signing_key(key_a0_id, key_a0)
            .unwrap();
    }

    #[test]
    fn test_set_keys_for_encryption() {
        let store: KeyStore<TestIds> = KeyStore::default();

        // Generate and insert a key
        let key_a0_id = TestSymmKey::A(0);
        let key_a0 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        store
            .context_mut()
            .set_symmetric_key(TestSymmKey::A(0), key_a0.clone())
            .unwrap();

        assert!(store.context().has_symmetric_key(key_a0_id));

        // Encrypt some data with the key
        let data = DataView("Hello, World!".to_string(), key_a0_id);
        let _encrypted: Data = data
            .encrypt_composite(&mut store.context(), key_a0_id)
            .unwrap();
    }

    #[test]
    fn test_key_encryption() {
        let store: KeyStore<TestIds> = KeyStore::default();

        let mut ctx = store.context();

        // Generate and insert a key
        let key_1_id = TestSymmKey::C(1);
        let key_1 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        ctx.set_symmetric_key(key_1_id, key_1.clone()).unwrap();

        assert!(ctx.has_symmetric_key(key_1_id));

        // Generate and insert a new key
        let key_2_id = TestSymmKey::C(2);
        let key_2 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        ctx.set_symmetric_key(key_2_id, key_2.clone()).unwrap();

        assert!(ctx.has_symmetric_key(key_2_id));

        // Encrypt the new key with the old key
        let key_2_enc = ctx.wrap_symmetric_key(key_1_id, key_2_id).unwrap();

        // Decrypt the new key with the old key in a different identifier
        let new_key_id = TestSymmKey::C(3);

        ctx.unwrap_symmetric_key(key_1_id, new_key_id, &key_2_enc)
            .unwrap();

        // Now `key_2_id` and `new_key_id` contain the same key, so we should be able to encrypt
        // with one and decrypt with the other

        let data = DataView("Hello, World!".to_string(), key_2_id);
        let encrypted = data.encrypt_composite(&mut ctx, key_2_id).unwrap();

        let decrypted1 = encrypted.decrypt(&mut ctx, key_2_id).unwrap();
        let decrypted2 = encrypted.decrypt(&mut ctx, new_key_id).unwrap();

        // Assert that the decrypted data is the same
        assert_eq!(decrypted1.0, decrypted2.0);
    }

    #[test]
    fn test_wrap_unwrap() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Aes256 CBC HMAC keys
        let key_aes_1_id = TestSymmKey::A(1);
        let key_aes_1 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        ctx.set_symmetric_key(key_aes_1_id, key_aes_1.clone())
            .unwrap();
        let key_aes_2_id = TestSymmKey::A(2);
        let key_aes_2 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        ctx.set_symmetric_key(key_aes_2_id, key_aes_2.clone())
            .unwrap();

        // XChaCha20 Poly1305 keys
        let key_xchacha_3_id = TestSymmKey::A(3);
        let key_xchacha_3 = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        ctx.set_symmetric_key(key_xchacha_3_id, key_xchacha_3.clone())
            .unwrap();
        let key_xchacha_4_id = TestSymmKey::A(4);
        let key_xchacha_4 = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        ctx.set_symmetric_key(key_xchacha_4_id, key_xchacha_4.clone())
            .unwrap();

        // Wrap and unwrap the keys
        let wrapped_key_1_2 = ctx.wrap_symmetric_key(key_aes_1_id, key_aes_2_id).unwrap();
        let wrapped_key_1_3 = ctx
            .wrap_symmetric_key(key_aes_1_id, key_xchacha_3_id)
            .unwrap();
        let wrapped_key_3_1 = ctx
            .wrap_symmetric_key(key_xchacha_3_id, key_aes_1_id)
            .unwrap();
        let wrapped_key_3_4 = ctx
            .wrap_symmetric_key(key_xchacha_3_id, key_xchacha_4_id)
            .unwrap();

        // Unwrap the keys
        let unwrapped_key_2 = ctx
            .unwrap_symmetric_key(key_aes_1_id, key_aes_2_id, &wrapped_key_1_2)
            .unwrap();
        let unwrapped_key_3 = ctx
            .unwrap_symmetric_key(key_aes_1_id, key_xchacha_3_id, &wrapped_key_1_3)
            .unwrap();
        let unwrapped_key_1 = ctx
            .unwrap_symmetric_key(key_xchacha_3_id, key_aes_1_id, &wrapped_key_3_1)
            .unwrap();
        let unwrapped_key_4 = ctx
            .unwrap_symmetric_key(key_xchacha_3_id, key_xchacha_4_id, &wrapped_key_3_4)
            .unwrap();

        // Assert that the unwrapped keys are the same as the original keys
        assert_eq!(unwrapped_key_2, key_aes_2_id);
        assert_eq!(unwrapped_key_3, key_xchacha_3_id);
        assert_eq!(unwrapped_key_1, key_aes_1_id);
        assert_eq!(unwrapped_key_4, key_xchacha_4_id);
    }

    #[test]
    fn test_signing() {
        let store: KeyStore<TestIds> = KeyStore::default();

        // Generate and insert a key
        let key_a0_id = TestSigningKey::A(0);
        let key_a0 = SigningKey::make(SignatureAlgorithm::Ed25519);
        let verifying_key = key_a0.to_verifying_key();
        store
            .context_mut()
            .set_signing_key(key_a0_id, key_a0)
            .unwrap();

        assert!(store.context().has_signing_key(key_a0_id));

        // Sign some data with the key
        #[derive(Serialize, Deserialize)]
        struct TestData {
            data: String,
        }
        let signed_object = store
            .context()
            .sign(
                key_a0_id,
                &TestData {
                    data: "Hello".to_string(),
                },
                &SigningNamespace::ExampleNamespace,
            )
            .unwrap();
        let payload: Result<TestData, CryptoError> =
            signed_object.verify_and_unwrap(&verifying_key, &SigningNamespace::ExampleNamespace);
        assert!(payload.is_ok());

        let (signature, serialized_message) = store
            .context()
            .sign_detached(
                key_a0_id,
                &TestData {
                    data: "Hello".to_string(),
                },
                &SigningNamespace::ExampleNamespace,
            )
            .unwrap();
        assert!(signature.verify(
            serialized_message.as_bytes(),
            &verifying_key,
            &SigningNamespace::ExampleNamespace
        ))
    }

    #[test]
    fn test_account_key_rotation() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Generate a new user key
        let current_user_private_key_id = TestAsymmKey::A(0);
        let current_user_signing_key_id = TestSigningKey::A(0);

        // Make the keys
        ctx.generate_symmetric_key(TestSymmKey::A(0)).unwrap();
        ctx.make_signing_key(current_user_signing_key_id).unwrap();
        ctx.set_asymmetric_key(
            current_user_private_key_id,
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1),
        )
        .unwrap();

        // Get the rotated account keys
        let rotated_keys = ctx
            .dangerous_get_v2_rotated_account_keys(
                current_user_private_key_id,
                current_user_signing_key_id,
            )
            .unwrap();

        // Public/Private key
        assert_eq!(
            AsymmetricPublicCryptoKey::from_der(&rotated_keys.public_key)
                .unwrap()
                .to_der()
                .unwrap(),
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_public_key()
                .to_der()
                .unwrap()
        );
        let decrypted_private_key: Vec<u8> = rotated_keys
            .private_key
            .decrypt_with_key(&rotated_keys.user_key)
            .unwrap();
        let private_key =
            AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(decrypted_private_key))
                .unwrap();
        assert_eq!(
            private_key.to_der().unwrap(),
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_der()
                .unwrap()
        );

        // Signing Key
        let decrypted_signing_key: Vec<u8> = rotated_keys
            .signing_key
            .decrypt_with_key(&rotated_keys.user_key)
            .unwrap();
        let signing_key =
            SigningKey::from_cose(&CoseKeyBytes::from(decrypted_signing_key)).unwrap();
        assert_eq!(
            signing_key.to_cose(),
            ctx.get_signing_key(current_user_signing_key_id)
                .unwrap()
                .to_cose(),
        );

        // Signed Public Key
        let signed_public_key = rotated_keys.signed_public_key;
        let unwrapped_key = signed_public_key
            .verify_and_unwrap(
                &ctx.get_signing_key(current_user_signing_key_id)
                    .unwrap()
                    .to_verifying_key(),
            )
            .unwrap();
        assert_eq!(
            unwrapped_key.to_der().unwrap(),
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_public_key()
                .to_der()
                .unwrap()
        );
    }
}
