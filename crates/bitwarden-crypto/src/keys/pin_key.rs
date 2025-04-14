use super::{
    utils::stretch_key,
};
use crate::{
    kdf::{Kdf, KdfDerivedKeyMaterial}, keys::key_encryptable::CryptoKey, EncString, KeyEncryptable, Result, SymmetricCryptoKey
};

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
    pub fn encrypt_user_key(&self, user_key: &SymmetricCryptoKey) -> Result<EncString> {
        // encrypt_key_with_password(&self.0.material, user_key)
        todo!();
    }

    /// Decrypt the users user key
    pub fn decrypt_user_key(password: &[u8], email: &[u8], kdf: &Kdf, user_key: EncString) -> Result<SymmetricCryptoKey> {
        // decrypt_key_with_password(password, email, kdf, user_key)
        todo!();
    }
}

impl CryptoKey for PinKey {}

impl KeyEncryptable<PinKey, EncString> for &[u8] {
    fn encrypt_with_key(self, key: &PinKey) -> Result<EncString> {
        let stretched_key = SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(&key.0.material)?);
        self.encrypt_with_key(&stretched_key)
    }
}

impl KeyEncryptable<PinKey, EncString> for String {
    fn encrypt_with_key(self, key: &PinKey) -> Result<EncString> {
        self.as_bytes().encrypt_with_key(key)
    }
}
