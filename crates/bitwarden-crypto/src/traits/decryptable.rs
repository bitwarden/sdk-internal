use crate::{CryptoError, EncString, KeyId, KeyIds, store::KeyStoreContext};

/// A decryption operation that takes the input value and decrypts it into the output value.
/// Implementations should generally consist of calling [Decryptable::decrypt] for all the fields of
/// the type.
pub trait Decryptable<Ids: KeyIds, Key: KeyId, Output> {
    #[allow(missing_docs)]
    fn decrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: Key) -> Result<Output, CryptoError>;
}

impl<Ids: KeyIds> Decryptable<Ids, Ids::Symmetric, Vec<u8>> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<Vec<u8>, CryptoError> {
        ctx.decrypt_data_with_symmetric_key(key, self)
    }
}

impl<Ids: KeyIds> Decryptable<Ids, Ids::Symmetric, String> for EncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<String, CryptoError> {
        let bytes: Vec<u8> = self.decrypt(ctx, key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

impl<Ids: KeyIds, Key: KeyId, T: Decryptable<Ids, Key, Output>, Output>
    Decryptable<Ids, Key, Option<Output>> for Option<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Option<Output>, CryptoError> {
        self.as_ref()
            .map(|value| value.decrypt(ctx, key))
            .transpose()
    }
}

impl<Ids: KeyIds, Key: KeyId, T: Decryptable<Ids, Key, Output>, Output>
    Decryptable<Ids, Key, Vec<Output>> for Vec<T>
{
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Key,
    ) -> Result<Vec<Output>, CryptoError> {
        self.iter().map(|value| value.decrypt(ctx, key)).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Decryptable, EncString, KeyStore, SymmetricCryptoKey, traits::tests::*};

    fn test_store() -> KeyStore<TestIds> {
        let store = KeyStore::<TestIds>::default();

        let key = SymmetricCryptoKey::try_from("sJnO8rVi0dTwND43n0T9x7665s8mVUYNAaJ4nm7gx1iia1I7947URL60nwfIHaf9QJePO4VkNN0oT9jh4iC6aA==".to_string()).unwrap();

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(TestSymmKey::A(0), key.clone())
            .unwrap();

        store
    }

    #[test]
    fn test_decryptable_bytes() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let data_encrypted: EncString = "2.kTtIypq9OLzd5iMMbU11pQ==|J4i3hTtGVdg7EZ+AQv/ujg==|QJpSpotQVpIW8j8dR/8l015WJzAIxBaOmrz4Uj/V1JA=".parse().unwrap();

        let data_decrypted: Vec<u8> = data_encrypted.decrypt(&mut ctx, key).unwrap();
        assert_eq!(data_decrypted, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_decryptable_string() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let data_encrypted: EncString = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=".parse().unwrap();

        let data_decrypted: String = data_encrypted.decrypt(&mut ctx, key).unwrap();
        assert_eq!(data_decrypted, "Hello, World!");
    }

    #[test]
    fn test_decryptable_option_some() {
        let store = test_store();
        let mut ctx = store.context();
        let key = TestSymmKey::A(0);

        let data_encrypted: EncString = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=".parse().unwrap();
        let data_encrypted_some = Some(data_encrypted);

        let string_decrypted: Option<String> = data_encrypted_some.decrypt(&mut ctx, key).unwrap();
        assert_eq!(string_decrypted, Some("Hello, World!".to_string()));
    }

    #[test]
    fn test_decryptable_option_none() {
        let store = test_store();
        let mut ctx = store.context();

        let key = TestSymmKey::A(0);
        let none_data: Option<EncString> = None;
        let string_decrypted: Option<String> = none_data.decrypt(&mut ctx, key).unwrap();
        assert_eq!(string_decrypted, None);

        // The None implementation will not do any decrypt operations, so it won't fail even if the
        // key doesn't exist
        let bad_key = TestSymmKey::B((0, 1));
        let string_decrypted_bad: Option<String> = none_data.decrypt(&mut ctx, bad_key).unwrap();
        assert_eq!(string_decrypted_bad, None);
    }
}
