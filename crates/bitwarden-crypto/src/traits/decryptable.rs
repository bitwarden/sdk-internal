use crate::{store::KeyStoreContext, AsymmetricEncString, CryptoError, EncString, KeyId, KeyIds};

/// A decryption operation that takes the input value and decrypts it into the output value.
/// Implementations should generally consist of calling [Decryptable::decrypt] for all the fields of
/// the type.
pub trait Decryptable<Ids: KeyIds, Key: KeyId, Output> {
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

impl<Ids: KeyIds> Decryptable<Ids, Ids::Asymmetric, Vec<u8>> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<Vec<u8>, CryptoError> {
        ctx.decrypt_data_with_asymmetric_key(key, self)
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

impl<Ids: KeyIds> Decryptable<Ids, Ids::Asymmetric, String> for AsymmetricEncString {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
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
