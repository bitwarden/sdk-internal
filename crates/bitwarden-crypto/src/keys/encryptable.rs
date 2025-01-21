use crate::{store::KeyStoreContext, AsymmetricEncString, CryptoError, EncString, KeyId, KeyIds};

/// Types implementing [UsesKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait UsesKey<Key: KeyId> {
    fn uses_key(&self) -> Key;
}

/// An encryption operation that takes the input value and encrypts it into the output value.
/// Implementations should generally consist of calling [Encryptable::encrypt] for all the fields of
/// the type.
pub trait Encryptable<Ids: KeyIds, Key: KeyId, Output> {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Output, crate::CryptoError>;
}

/// A decryption operation that takes the input value and decrypts it into the output value.
/// Implementations should generally consist of calling [Decryptable::decrypt] for all the fields of
/// the type.
pub trait Decryptable<Ids: KeyIds, Key: KeyId, Output> {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Output, crate::CryptoError>;
}

// Basic Encryptable/Decryptable implementations to and from bytes

impl<Ids: KeyIds> Decryptable<Ids, Ids::Symmetric, Vec<u8>> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        ctx.decrypt_data_with_symmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Decryptable<Ids, Ids::Asymmetric, Vec<u8>> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        ctx.decrypt_data_with_asymmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        ctx.encrypt_data_with_asymmetric_key(key, self)
    }
}

// Encryptable/Decryptable implementations to and from strings

impl<Ids: KeyIds> Decryptable<Ids, Ids::Symmetric, String> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<String, crate::CryptoError> {
        let bytes: Vec<u8> = self.decrypt(ctx, key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

impl<Ids: KeyIds> Decryptable<Ids, Ids::Asymmetric, String> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<String, crate::CryptoError> {
        let bytes: Vec<u8> = self.decrypt(ctx, key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

// Generic implementations for Optional values

impl<Ids: KeyIds, Key: KeyId, T: Encryptable<Ids, Key, Output>, Output>
    Encryptable<Ids, Key, Option<Output>> for Option<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Option<Output>, crate::CryptoError> {
        self.as_ref()
            .map(|value| value.encrypt(ctx, key))
            .transpose()
    }
}

impl<Ids: KeyIds, Key: KeyId, T: Decryptable<Ids, Key, Output>, Output>
    Decryptable<Ids, Key, Option<Output>> for Option<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Option<Output>, crate::CryptoError> {
        self.as_ref()
            .map(|value| value.decrypt(ctx, key))
            .transpose()
    }
}

// Generic implementations for Vec values

impl<Ids: KeyIds, Key: KeyId, T: Encryptable<Ids, Key, Output>, Output>
    Encryptable<Ids, Key, Vec<Output>> for Vec<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Vec<Output>, crate::CryptoError> {
        self.iter().map(|value| value.encrypt(ctx, key)).collect()
    }
}

impl<Ids: KeyIds, Key: KeyId, T: Decryptable<Ids, Key, Output>, Output>
    Decryptable<Ids, Key, Vec<Output>> for Vec<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Vec<Output>, crate::CryptoError> {
        self.iter().map(|value| value.decrypt(ctx, key)).collect()
    }
}
