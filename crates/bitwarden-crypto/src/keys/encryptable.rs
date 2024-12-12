use crate::{store::KeyStoreContext, AsymmetricEncString, CryptoError, EncString, KeyRef, KeyRefs};

/// Types implementing [UsesKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait UsesKey<Key: KeyRef> {
    fn uses_key(&self) -> Key;
}

/// An encryption operation that takes the input value and encrypts it into the output value.
/// Implementations should generally consist of calling [Encryptable::encrypt] for all the fields of the type.
pub trait Encryptable<Refs: KeyRefs, Key: KeyRef, Output> {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Output, crate::CryptoError>;
}

/// A decryption operation that takes the input value and decrypts it into the output value.
/// Implementations should generally consist of calling [Decryptable::decrypt] for all the fields of the type.
pub trait Decryptable<Refs: KeyRefs, Key: KeyRef, Output> {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Output, crate::CryptoError>;
}

// Basic Encryptable/Decryptable implementations to and from bytes

impl<Refs: KeyRefs> Decryptable<Refs, Refs::Symmetric, Vec<u8>> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Symmetric,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        ctx.decrypt_data_with_symmetric_key(key, self)
    }
}

impl<Refs: KeyRefs> Decryptable<Refs, Refs::Asymmetric, Vec<u8>> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Asymmetric,
    ) -> Result<Vec<u8>, crate::CryptoError> {
        ctx.decrypt_data_with_asymmetric_key(key, self)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Symmetric, EncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Asymmetric, AsymmetricEncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        ctx.encrypt_data_with_asymmetric_key(key, self)
    }
}

// Encryptable/Decryptable implementations to and from strings

impl<Refs: KeyRefs> Decryptable<Refs, Refs::Symmetric, String> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Symmetric,
    ) -> Result<String, crate::CryptoError> {
        let bytes: Vec<u8> = self.decrypt(ctx, key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

impl<Refs: KeyRefs> Decryptable<Refs, Refs::Asymmetric, String> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Asymmetric,
    ) -> Result<String, crate::CryptoError> {
        let bytes: Vec<u8> = self.decrypt(ctx, key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Symmetric, EncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Asymmetric, AsymmetricEncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Symmetric, EncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Symmetric,
    ) -> Result<EncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Refs: KeyRefs> Encryptable<Refs, Refs::Asymmetric, AsymmetricEncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Refs::Asymmetric,
    ) -> Result<AsymmetricEncString, crate::CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

// Generic implementations for Optional values

impl<Refs: KeyRefs, Key: KeyRef, T: Encryptable<Refs, Key, Output>, Output>
    Encryptable<Refs, Key, Option<Output>> for Option<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Option<Output>, crate::CryptoError> {
        self.as_ref()
            .map(|value| value.encrypt(ctx, key))
            .transpose()
    }
}

impl<Refs: KeyRefs, Key: KeyRef, T: Decryptable<Refs, Key, Output>, Output>
    Decryptable<Refs, Key, Option<Output>> for Option<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Option<Output>, crate::CryptoError> {
        self.as_ref()
            .map(|value| value.decrypt(ctx, key))
            .transpose()
    }
}

// Generic implementations for Vec values

impl<Refs: KeyRefs, Key: KeyRef, T: Encryptable<Refs, Key, Output>, Output>
    Encryptable<Refs, Key, Vec<Output>> for Vec<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Vec<Output>, crate::CryptoError> {
        self.iter().map(|value| value.encrypt(ctx, key)).collect()
    }
}

impl<Refs: KeyRefs, Key: KeyRef, T: Decryptable<Refs, Key, Output>, Output>
    Decryptable<Refs, Key, Vec<Output>> for Vec<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Refs>,
        key: Key,
    ) -> Result<Vec<Output>, crate::CryptoError> {
        self.iter().map(|value| value.decrypt(ctx, key)).collect()
    }
}
