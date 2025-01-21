use crate::{store::KeyStoreContext, AsymmetricEncString, CryptoError, EncString, KeyId, KeyIds};

/// An encryption operation that takes the input value and encrypts it into the output value.
/// Implementations should generally consist of calling [Encryptable::encrypt] for all the fields of
/// the type.
pub trait Encryptable<Ids: KeyIds, Key: KeyId, Output> {
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

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for &[u8] {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, CryptoError> {
        ctx.encrypt_data_with_asymmetric_key(key, self)
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

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for &str {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, CryptoError> {
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

impl<Ids: KeyIds> Encryptable<Ids, Ids::Asymmetric, AsymmetricEncString> for String {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString, CryptoError> {
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
