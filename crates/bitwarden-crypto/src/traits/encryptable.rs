use crate::{store::KeyStoreContext, CryptoError, EncString, KeyId, KeyIds};

/// An encryption operation that takes the input value and encrypts it into the output value.
/// Implementations should generally consist of calling [Encryptable::encrypt] for all the fields of
/// the type.
pub trait Encryptable<Ids: KeyIds, Key: KeyId, Output> {
    #[allow(missing_docs)]
    fn encrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: Key) -> Result<Output, CryptoError>;
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for Vec<u8> {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        ctx.encrypt_data_with_symmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Ids: KeyIds> Encryptable<Ids, Ids::Symmetric, EncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.as_bytes().encrypt(ctx, key)
    }
}

impl<Ids: KeyIds, Key: KeyId, T: Encryptable<Ids, Key, Output>, Output>
    Encryptable<Ids, Key, Option<Output>> for Option<T>
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

impl<Ids: KeyIds, Key: KeyId, T: Encryptable<Ids, Key, Output>, Output>
    Encryptable<Ids, Key, Vec<Output>> for Vec<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Vec<Output>, CryptoError> {
        self.iter().map(|value| value.encrypt(ctx, key)).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        traits::tests::*, AsymmetricCryptoKey, Decryptable, Encryptable, KeyStore,
        SymmetricCryptoKey,
    };

    fn test_store() -> KeyStore<TestIds> {
        let store = KeyStore::<TestIds>::default();

        let symm_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let asymm_key = AsymmetricCryptoKey::generate(&mut rand::thread_rng());

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

        let vec_encrypted = vec_data.encrypt(&mut ctx, key).unwrap();
        let slice_encrypted = slice_data.encrypt(&mut ctx, key).unwrap();

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
