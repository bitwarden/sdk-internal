use tracing::instrument;

use crate::{
    BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey,
};

/// Local user data key.
///
/// An indirect symmetric key for encrypting local user data (e.g. password generator history).
/// Enables offline decryption of local data after a key rotation: only the wrapped key is
/// re-encrypted; the local user data key itself stays intact.
#[derive(Clone)]
pub enum LocalUserDataKey {
    /// Derived from the user key.
    ///
    /// Used for backwards compatibility: data previously encrypted with the user key can be
    /// decrypted by the reconstructed `SymmetricCryptoKey`.
    DerivedFromUserKey(BitwardenLegacyKeyBytes),
}

impl LocalUserDataKey {
    /// Create a `LocalUserDataKey` from the user key for backwards compatibility.
    ///
    /// The encoded key bytes are stored so the original `SymmetricCryptoKey` can be extracted,
    /// enabling decryption of data previously encrypted with the user key.
    pub fn from_user_key(user_key: &SymmetricCryptoKey) -> Self {
        LocalUserDataKey::DerivedFromUserKey(user_key.to_encoded())
    }

    /// Wrap (encrypt) this key with the given user key for protected storage.
    #[cfg_attr(feature = "dangerous-crypto-debug", instrument(err))]
    #[cfg_attr(not(feature = "dangerous-crypto-debug"), instrument(skip_all, err))]
    pub fn encrypt_with_user_key(
        &self,
        user_key: &SymmetricCryptoKey,
    ) -> crate::error::Result<EncString> {
        let encoded_key = match self {
            LocalUserDataKey::DerivedFromUserKey(k) => k.clone(),
        };
        encoded_key.encrypt_with_key(user_key)
    }

    /// Unwrap (decrypt) a `LocalUserDataKey` previously wrapped with the given user key.
    #[cfg_attr(feature = "dangerous-crypto-debug", instrument(err))]
    #[cfg_attr(not(feature = "dangerous-crypto-debug"), instrument(skip_all, err))]
    pub fn decrypt_with_user_key(
        user_key: &SymmetricCryptoKey,
        encrypted: EncString,
    ) -> crate::error::Result<Self> {
        let dec: Vec<u8> = encrypted.decrypt_with_key(user_key)?;
        let key_bytes = BitwardenLegacyKeyBytes::from(dec);
        SymmetricCryptoKey::try_from(&key_bytes)?; // validate
        Ok(LocalUserDataKey::DerivedFromUserKey(key_bytes))
    }
}

impl std::fmt::Debug for LocalUserDataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("LocalUserDataKey");
        match self {
            LocalUserDataKey::DerivedFromUserKey(_key) => {
                debug_struct.field("variant", &"DerivedFromUserKey");
                #[cfg(feature = "dangerous-crypto-debug")]
                debug_struct.field("key", &SymmetricCryptoKey::try_from(_key).ok());
            }
        }
        debug_struct.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::LocalUserDataKey;
    use crate::SymmetricCryptoKey;

    fn as_symmetric_key(key: &LocalUserDataKey) -> SymmetricCryptoKey {
        match key {
            LocalUserDataKey::DerivedFromUserKey(k) => SymmetricCryptoKey::try_from(k).unwrap(),
        }
    }

    #[test]
    fn test_from_user_key_aes256_cbc_hmac() {
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let local_key = LocalUserDataKey::from_user_key(&user_key);
        let extracted = as_symmetric_key(&local_key);
        assert_eq!(user_key, extracted, "Extracted key must equal user key");
    }

    #[test]
    fn test_from_user_key_xchacha20_poly1305() {
        let user_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let local_key = LocalUserDataKey::from_user_key(&user_key);
        let extracted = as_symmetric_key(&local_key);
        assert_eq!(user_key, extracted, "Extracted key must equal user key");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        let local_key = LocalUserDataKey::from_user_key(&user_key);
        let wrapped = local_key.encrypt_with_user_key(&user_key).unwrap();
        let unwrapped = LocalUserDataKey::decrypt_with_user_key(&user_key, wrapped).unwrap();

        let original = as_symmetric_key(&local_key);
        let decrypted = as_symmetric_key(&unwrapped);
        assert_eq!(original, decrypted, "Decrypted key must match original");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_xchacha20() {
        let user_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();

        let local_key = LocalUserDataKey::from_user_key(&user_key);
        let wrapped = local_key.encrypt_with_user_key(&user_key).unwrap();
        let unwrapped = LocalUserDataKey::decrypt_with_user_key(&user_key, wrapped).unwrap();

        let original = as_symmetric_key(&local_key);
        let decrypted = as_symmetric_key(&unwrapped);
        assert_eq!(original, decrypted, "Decrypted key must match original");
    }
}
