use std::sync::{RwLockReadGuard, RwLockWriteGuard};

use rsa::Oaep;
use zeroize::Zeroizing;

use super::KeyStoreInner;
use crate::{
    derive_shareable_key, store::backend::StoreBackend, AsymmetricCryptoKey, AsymmetricEncString,
    CryptoError, EncString, KeyRef, KeyRefs, Result, SymmetricCryptoKey,
};

pub struct KeyStoreContext<'a, Refs: KeyRefs> {
    pub(super) global_keys: GlobalKeys<'a, Refs>,

    pub(super) local_symmetric_keys: Box<dyn StoreBackend<Refs::Symmetric>>,
    pub(super) local_asymmetric_keys: Box<dyn StoreBackend<Refs::Asymmetric>>,

    pub(super) _phantom: std::marker::PhantomData<&'a ()>,
}

// A KeyStoreContext is usually limited to a read only access to the global keys,
// which allows us to have multiple read only contexts at the same time and do multitheaded
// encryption/decryption. We also have the option to create a read/write context, which allows us to
// modify the global keys, but only allows one context at a time. This is controlled by a RWLock on
// the global keys, and this struct stores both types of guards.
pub(crate) enum GlobalKeys<'a, Refs: KeyRefs> {
    ReadOnly(RwLockReadGuard<'a, KeyStoreInner<Refs>>),
    ReadWrite(RwLockWriteGuard<'a, KeyStoreInner<Refs>>),
}

impl<Refs: KeyRefs> GlobalKeys<'_, Refs> {
    pub fn get(&self) -> &KeyStoreInner<Refs> {
        match self {
            GlobalKeys::ReadOnly(keys) => keys,
            GlobalKeys::ReadWrite(keys) => keys,
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut KeyStoreInner<Refs>> {
        match self {
            GlobalKeys::ReadOnly(_) => Err(CryptoError::ReadOnlyKeyStore),
            GlobalKeys::ReadWrite(keys) => Ok(keys),
        }
    }
}

impl<Refs: KeyRefs> KeyStoreContext<'_, Refs> {
    pub fn clear(&mut self) {
        // Clear global keys if we have write access
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.symmetric_keys.clear();
            keys.asymmetric_keys.clear();
        }

        self.local_symmetric_keys.clear();
        self.local_asymmetric_keys.clear();
    }

    pub fn retain_symmetric_keys(&mut self, f: fn(Refs::Symmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.symmetric_keys.retain(f);
        }
        self.local_symmetric_keys.retain(f);
    }

    pub fn retain_asymmetric_keys(&mut self, f: fn(Refs::Asymmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.asymmetric_keys.retain(f);
        }
        self.local_asymmetric_keys.retain(f);
    }

    // TODO: All these encrypt x key with x key look like they need to be made generic,
    // but I haven't found the best way to do that yet.

    pub fn decrypt_symmetric_key_with_symmetric_key(
        &mut self,
        encryption_key: Refs::Symmetric,
        new_key_ref: Refs::Symmetric,
        encrypted_key: &EncString,
    ) -> Result<Refs::Symmetric> {
        let mut new_key_material =
            self.decrypt_data_with_symmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_symmetric_key(
            new_key_ref,
            SymmetricCryptoKey::try_from(new_key_material.as_mut_slice())?,
        )?;

        // Returning the new key reference for convenience
        Ok(new_key_ref)
    }

    pub fn encrypt_symmetric_key_with_symmetric_key(
        &self,
        encryption_key: Refs::Symmetric,
        key_to_encrypt: Refs::Symmetric,
    ) -> Result<EncString> {
        let key_to_encrypt = self.get_symmetric_key(key_to_encrypt)?;
        self.encrypt_data_with_symmetric_key(encryption_key, &key_to_encrypt.to_vec())
    }

    pub fn decrypt_symmetric_key_with_asymmetric_key(
        &mut self,
        encryption_key: Refs::Asymmetric,
        new_key_ref: Refs::Symmetric,
        encrypted_key: &AsymmetricEncString,
    ) -> Result<Refs::Symmetric> {
        let mut new_key_material =
            self.decrypt_data_with_asymmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_symmetric_key(
            new_key_ref,
            SymmetricCryptoKey::try_from(new_key_material.as_mut_slice())?,
        )?;

        // Returning the new key reference for convenience
        Ok(new_key_ref)
    }

    pub fn encrypt_symmetric_key_with_asymmetric_key(
        &self,
        encryption_key: Refs::Asymmetric,
        key_to_encrypt: Refs::Symmetric,
    ) -> Result<AsymmetricEncString> {
        let key_to_encrypt = self.get_symmetric_key(key_to_encrypt)?;
        self.encrypt_data_with_asymmetric_key(encryption_key, &key_to_encrypt.to_vec())
    }

    pub fn decrypt_asymmetric_key(
        &mut self,
        encryption_key: Refs::Asymmetric,
        new_key_ref: Refs::Asymmetric,
        encrypted_key: &AsymmetricEncString,
    ) -> Result<Refs::Asymmetric> {
        let new_key_material =
            self.decrypt_data_with_asymmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_asymmetric_key(
            new_key_ref,
            AsymmetricCryptoKey::from_der(&new_key_material)?,
        )?;

        // Returning the new key reference for convenience
        Ok(new_key_ref)
    }

    pub fn encrypt_asymmetric_key(
        &self,
        encryption_key: Refs::Asymmetric,
        key_to_encrypt: Refs::Asymmetric,
    ) -> Result<AsymmetricEncString> {
        let encryption_key = self.get_asymmetric_key(encryption_key)?;
        let key_to_encrypt = self.get_asymmetric_key(key_to_encrypt)?;

        AsymmetricEncString::encrypt_rsa2048_oaep_sha1(
            key_to_encrypt.to_der()?.as_slice(),
            encryption_key,
        )
    }

    pub fn has_symmetric_key(&self, key_ref: Refs::Symmetric) -> bool {
        self.get_symmetric_key(key_ref).is_ok()
    }

    pub fn has_asymmetric_key(&self, key_ref: Refs::Asymmetric) -> bool {
        self.get_asymmetric_key(key_ref).is_ok()
    }

    pub fn generate_symmetric_key(&mut self, key_ref: Refs::Symmetric) -> Result<Refs::Symmetric> {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        #[allow(deprecated)]
        self.set_symmetric_key(key_ref, key)?;
        Ok(key_ref)
    }

    pub fn derive_shareable_key(
        &mut self,
        key_ref: Refs::Symmetric,
        secret: Zeroizing<[u8; 16]>,
        name: &str,
        info: Option<&str>,
    ) -> Result<Refs::Symmetric> {
        #[allow(deprecated)]
        self.set_symmetric_key(key_ref, derive_shareable_key(secret, name, info))?;
        Ok(key_ref)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn dangerous_get_symmetric_key(
        &self,
        key_ref: Refs::Symmetric,
    ) -> Result<&SymmetricCryptoKey> {
        self.get_symmetric_key(key_ref)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn dangerous_get_asymmetric_key(
        &self,
        key_ref: Refs::Asymmetric,
    ) -> Result<&AsymmetricCryptoKey> {
        self.get_asymmetric_key(key_ref)
    }

    fn get_symmetric_key(&self, key_ref: Refs::Symmetric) -> Result<&SymmetricCryptoKey> {
        if key_ref.is_local() {
            self.local_symmetric_keys.get(key_ref)
        } else {
            self.global_keys.get().symmetric_keys.get(key_ref)
        }
        .ok_or_else(|| crate::CryptoError::MissingKey2(format!("{key_ref:?}")))
    }

    fn get_asymmetric_key(&self, key_ref: Refs::Asymmetric) -> Result<&AsymmetricCryptoKey> {
        if key_ref.is_local() {
            self.local_asymmetric_keys.get(key_ref)
        } else {
            self.global_keys.get().asymmetric_keys.get(key_ref)
        }
        .ok_or_else(|| crate::CryptoError::MissingKey2(format!("{key_ref:?}")))
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_symmetric_key(
        &mut self,
        key_ref: Refs::Symmetric,
        key: SymmetricCryptoKey,
    ) -> Result<()> {
        if key_ref.is_local() {
            self.local_symmetric_keys.insert(key_ref, key);
        } else {
            self.global_keys
                .get_mut()?
                .symmetric_keys
                .insert(key_ref, key);
        }
        Ok(())
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_asymmetric_key(
        &mut self,
        key_ref: Refs::Asymmetric,
        key: AsymmetricCryptoKey,
    ) -> Result<()> {
        if key_ref.is_local() {
            self.local_asymmetric_keys.insert(key_ref, key);
        } else {
            self.global_keys
                .get_mut()?
                .asymmetric_keys
                .insert(key_ref, key);
        }
        Ok(())
    }

    pub(crate) fn decrypt_data_with_symmetric_key(
        &self,
        key: Refs::Symmetric,
        data: &EncString,
    ) -> Result<Vec<u8>> {
        let key = self.get_symmetric_key(key)?;

        match data {
            EncString::AesCbc256_B64 { iv, data } => {
                let dec = crate::aes::decrypt_aes256(iv, data.clone(), &key.key)?;
                Ok(dec)
            }
            EncString::AesCbc128_HmacSha256_B64 { iv, mac, data } => {
                // TODO: SymmetricCryptoKey is designed to handle 32 byte keys only, but this
                // variant uses a 16 byte key This means the key+mac are going to be
                // parsed as a single 32 byte key, at the moment we split it manually
                // When refactoring the key handling, this should be fixed.
                let enc_key = (&key.key[0..16]).into();
                let mac_key = (&key.key[16..32]).into();
                let dec = crate::aes::decrypt_aes128_hmac(iv, mac, data.clone(), mac_key, enc_key)?;
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
        key: Refs::Symmetric,
        data: &[u8],
    ) -> Result<EncString> {
        let key = self.get_symmetric_key(key)?;
        EncString::encrypt_aes256_hmac(
            data,
            key.mac_key.as_ref().ok_or(CryptoError::InvalidMac)?,
            &key.key,
        )
    }

    pub(crate) fn decrypt_data_with_asymmetric_key(
        &self,
        key: Refs::Asymmetric,
        data: &AsymmetricEncString,
    ) -> Result<Vec<u8>> {
        let key = self.get_asymmetric_key(key)?;

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
        key: Refs::Asymmetric,
        data: &[u8],
    ) -> Result<AsymmetricEncString> {
        let key = self.get_asymmetric_key(key)?;
        AsymmetricEncString::encrypt_rsa2048_oaep_sha1(data, key)
    }
}
