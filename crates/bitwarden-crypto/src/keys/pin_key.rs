use super::{
    kdf::{Kdf, KdfDerivedKeyMaterial},
    master_key::{decrypt_user_key, encrypt_user_key},
    utils::stretch_key,
};
use crate::{keys::key_encryptable::CryptoKey, EncString, Result, SymmetricCryptoKey};

/// Pin Key.
///
/// Derived from a specific password, used for pin encryption and exports.
pub struct PinKey(KdfDerivedKeyMaterial);

impl PinKey {
    /// Derives a users pin key from their password, email and KDF.
    pub fn derive(password: &[u8], email: &[u8], kdf: &Kdf) -> Result<Self> {
        KdfDerivedKeyMaterial::derive_kdf_key(password, email, kdf).map(Self)
    }

    /// Encrypt the users user key
    ///
    /// @param user_key: The user key to encrypt
    pub fn encrypt_user_key(&self, user_key: &SymmetricCryptoKey) -> Result<EncString> {
        encrypt_user_key(&self.0 .0, user_key)
    }

    /// Decrypt the users user key
    pub fn decrypt_user_key(&self, user_key: EncString) -> Result<SymmetricCryptoKey> {
        decrypt_user_key(&self.0 .0, user_key)
    }

    pub fn to_stretched_encryption_key(&self) -> Result<SymmetricCryptoKey> {
        Ok(SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(
            &self.0 .0,
        )?))
    }
}

impl CryptoKey for PinKey {}
