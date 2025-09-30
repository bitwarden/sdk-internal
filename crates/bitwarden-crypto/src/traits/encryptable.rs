//! This module defines traits for encrypting data. There are three categories here.
//!
//! Some (legacy) encryptables are made up of many small individually encrypted items. For instance,
//! a cipher is currently made up of many small `EncString`s and some further json objects that
//! themselves contain `EncString`s. The use of this is generally discouraged for new designs.
//! Still, this is generally the only trait that should be implemented outside of the crypto crate.
//!
//! Encrypting data directly, a content type must be provided, since an encrypted byte array alone
//! is not enough to tell the decryption code how to interpret the decrypted bytes. For this, there
//! are two traits, `PrimitiveEncryptable` and `PrimitiveEncryptableWithContentType`. The former
//! assumes that the implementation provides content format when encrypting, based on the type
//! of struct that is being encrypted. The latter allows the caller to specify the content format
//! at runtime, which is only allowed within the crypto crate.
//!
//! `PrimitiveEncryptable` is implemented for `crate::content_format::Bytes<C>` types, where `C` is
//! a type that implements the `ConstContentFormat` trait. This allows for compile-time type
//! checking of the content format, and the risk of using the wrong content format is limited to
//! converting untyped bytes into a `Bytes<C>`

use crate::{ContentFormat, CryptoError, EncString, KeyId, KeyIds, store::KeyStoreContext};

/// An encryption operation that takes the input value and encrypts the fields on it recursively.
/// Implementations should generally consist of calling [PrimitiveEncryptable::encrypt] for all the
/// fields of the type. Sometimes, it is necessary to call
/// [CompositeEncryptable::encrypt_composite], if the object is not a flat struct.
pub trait CompositeEncryptable<Ids: KeyIds, Key: KeyId, Output> {
    /// For a struct made up of many small encstrings, such as a cipher, this takes the struct
    /// and recursively encrypts all the fields / sub-structs.
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Output, CryptoError>;
}

impl<Ids: KeyIds, Key: KeyId, T: CompositeEncryptable<Ids, Key, Output>, Output>
    CompositeEncryptable<Ids, Key, Option<Output>> for Option<T>
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Option<Output>, CryptoError> {
        self.as_ref()
            .map(|value| value.encrypt_composite(ctx, key))
            .transpose()
    }
}

impl<Ids: KeyIds, Key: KeyId, T: CompositeEncryptable<Ids, Key, Output>, Output>
    CompositeEncryptable<Ids, Key, Vec<Output>> for Vec<T>
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Vec<Output>, CryptoError> {
        self.iter()
            .map(|value| value.encrypt_composite(ctx, key))
            .collect()
    }
}

/// An encryption operation that takes the input value - a primitive such as `String` and encrypts
/// it into the output value. The implementation decides the content format.
pub trait PrimitiveEncryptable<Ids: KeyIds, Key: KeyId, Output> {
    /// Encrypts a primitive without requiring an externally provided content type
    fn encrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: Key) -> Result<Output, CryptoError>;
}

impl<Ids: KeyIds, Key: KeyId, T: PrimitiveEncryptable<Ids, Key, Output>, Output>
    PrimitiveEncryptable<Ids, Key, Option<Output>> for Option<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Option<Output>, CryptoError> {
        self.as_ref()
            .map(|value| value.encrypt(ctx, key))
            .transpose()
    }
}

impl<Ids: KeyIds> PrimitiveEncryptable<Ids, Ids::Symmetric, EncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.as_bytes().encrypt(ctx, key, ContentFormat::Utf8)
    }
}

impl<Ids: KeyIds> PrimitiveEncryptable<Ids, Ids::Symmetric, EncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.as_bytes().encrypt(ctx, key, ContentFormat::Utf8)
    }
}

/// An encryption operation that takes the input value - a primitive such as `Vec<u8>` - and
/// encrypts it into the output value. The caller must specify the content format.
pub(crate) trait PrimitiveEncryptableWithContentType<Ids: KeyIds, Key: KeyId, Output> {
    /// Encrypts a primitive, given an externally provided content type
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
        content_format: ContentFormat,
    ) -> Result<Output, CryptoError>;
}

impl<Ids: KeyIds> PrimitiveEncryptableWithContentType<Ids, Ids::Symmetric, EncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
        content_format: ContentFormat,
    ) -> Result<EncString, CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self, content_format)
    }
}

impl<Ids: KeyIds> PrimitiveEncryptableWithContentType<Ids, Ids::Symmetric, EncString> for Vec<u8> {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
        content_format: ContentFormat,
    ) -> Result<EncString, CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self, content_format)
    }
}

impl<Ids: KeyIds, Key: KeyId, T: PrimitiveEncryptableWithContentType<Ids, Key, Output>, Output>
    PrimitiveEncryptableWithContentType<Ids, Key, Option<Output>> for Option<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
        content_format: crate::ContentFormat,
    ) -> Result<Option<Output>, CryptoError> {
        self.as_ref()
            .map(|value| value.encrypt(ctx, key, content_format))
            .transpose()
    }
}

impl<Ids: KeyIds, Key: KeyId, T: PrimitiveEncryptableWithContentType<Ids, Key, Output>, Output>
    PrimitiveEncryptableWithContentType<Ids, Key, Vec<Output>> for Vec<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
        content_format: ContentFormat,
    ) -> Result<Vec<Output>, CryptoError> {
        self.iter()
            .map(|value| value.encrypt(ctx, key, content_format))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AsymmetricCryptoKey, ContentFormat, Decryptable, KeyStore, PrimitiveEncryptable,
        PublicKeyEncryptionAlgorithm, SymmetricCryptoKey,
        traits::{encryptable::PrimitiveEncryptableWithContentType, tests::*},
    };

    fn test_store() -> KeyStore<TestIds> {
        let store = KeyStore::<TestIds>::default();

        let symm_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let asymm_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(TestSymmKey::A(0), symm_key.clone())
            .unwrap();
        #[allow(deprecated)]
        store
            .context_mut()
            .set_asymmetric_key(TestAsymmKey::A(0), asymm_key.clone())
            .unwrap();

        store
    }

    #[test]
    fn test_encryptable_bytes() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let vec_data = vec![1, 2, 3, 4, 5];
        let slice_data: &[u8] = &vec_data;

        let vec_encrypted = vec_data
            .encrypt(&mut ctx, key, ContentFormat::OctetStream)
            .unwrap();
        let slice_encrypted = slice_data
            .encrypt(&mut ctx, key, ContentFormat::OctetStream)
            .unwrap();

        let vec_decrypted: Vec<u8> = vec_encrypted.decrypt(&mut ctx, key).unwrap();
        let slice_decrypted: Vec<u8> = slice_encrypted.decrypt(&mut ctx, key).unwrap();

        assert_eq!(vec_data, vec_decrypted);
        assert_eq!(slice_data, slice_decrypted);
    }

    #[test]
    fn test_encryptable_string() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let string_data = "Hello, World!".to_string();
        let str_data: &str = string_data.as_str();

        let string_encrypted = string_data.encrypt(&mut ctx, key).unwrap();
        let str_encrypted = str_data.encrypt(&mut ctx, key).unwrap();

        let string_decrypted: String = string_encrypted.decrypt(&mut ctx, key).unwrap();
        let str_decrypted: String = str_encrypted.decrypt(&mut ctx, key).unwrap();

        assert_eq!(string_data, string_decrypted);
        assert_eq!(str_data, str_decrypted);
    }

    #[test]
    fn test_encryptable_option_some() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let string_data = Some("Hello, World!".to_string());

        let string_encrypted = string_data.encrypt(&mut ctx, key).unwrap();

        let string_decrypted: Option<String> = string_encrypted.decrypt(&mut ctx, key).unwrap();

        assert_eq!(string_data, string_decrypted);
    }

    #[test]
    fn test_encryptable_option_none() {
        let store = test_store();
        let mut ctx = store.context();

        let key = TestSymmKey::A(0);
        let none_data: Option<String> = None;
        let string_encrypted = none_data.encrypt(&mut ctx, key).unwrap();
        assert_eq!(string_encrypted, None);

        // The None implementation will not do any decrypt operations, so it won't fail even if the
        // key doesn't exist
        let bad_key = TestSymmKey::B((0, 1));
        let string_encrypted_bad = none_data.encrypt(&mut ctx, bad_key).unwrap();
        assert_eq!(string_encrypted_bad, None);
    }
}
