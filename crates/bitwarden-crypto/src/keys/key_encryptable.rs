use std::{collections::HashMap, hash::Hash, sync::Arc};

use rayon::prelude::*;
use uuid::Uuid;

use crate::{
    enc_string::encryption_context::EncryptionContextBuilder, error::Result, CryptoError,
    EncryptionContext, SymmetricCryptoKey,
};

pub trait KeyContainer: Send + Sync {
    fn get_key(&self, org_id: &Option<Uuid>) -> Result<&SymmetricCryptoKey, CryptoError>;
}

impl<T: KeyContainer> KeyContainer for Arc<T> {
    fn get_key(&self, org_id: &Option<Uuid>) -> Result<&SymmetricCryptoKey, CryptoError> {
        self.as_ref().get_key(org_id)
    }
}

pub trait LocateKey {
    fn locate_key<'a>(
        &self,
        enc: &'a dyn KeyContainer,
        org_id: &Option<Uuid>,
    ) -> Result<&'a SymmetricCryptoKey, CryptoError> {
        enc.get_key(org_id)
    }
}

pub trait CryptoKey {}

pub trait KeyEncryptable<Key: CryptoKey, Output, Context: EncryptionContext> {
    fn encrypt_with_key(self, key: &Key, context: &Context) -> Result<Output>;
}

pub trait KeyDecryptable<Key: CryptoKey, Output, ContextBuilder: EncryptionContextBuilder> {
    fn decrypt_with_key(&self, key: &Key, context_builder: &ContextBuilder) -> Result<Output>;
}

pub struct DecryptedWithAdditionalData {
    clear_text: Vec<u8>,
    additional_data: HashMap<String, String>,
}

impl DecryptedWithAdditionalData {
    pub fn new(clear_text: Vec<u8>, additional_data: HashMap<String, String>) -> Self {
        Self {
            clear_text,
            additional_data,
        }
    }

    pub fn clear_bytes(&self) -> &[u8] {
        &self.clear_text
    }

    pub fn clear_text_utf8(&self) -> Result<String> {
        String::from_utf8(self.clear_text.clone()).map_err(|_| CryptoError::InvalidUtf8String)
    }

    /// Additional data on the context of the decryption of the clear text.
    /// Note that not all of this data is authenticated for all [crate::EncString] variants.
    ///
    ///  See [KeyDecryptable<_,DecryptedWithAdditionalData>::decrypt_with_key] implementation for
    /// more information.
    pub fn additional_data(&self) -> &HashMap<String, String> {
        &self.additional_data
    }
}

impl<
        T: KeyEncryptable<Key, Output, Context>,
        Key: CryptoKey,
        Output,
        Context: EncryptionContext,
    > KeyEncryptable<Key, Option<Output>, Context> for Option<T>
{
    fn encrypt_with_key(self, key: &Key, context: &Context) -> Result<Option<Output>> {
        self.map(|e| e.encrypt_with_key(key, context)).transpose()
    }
}

impl<
        T: KeyDecryptable<Key, Output, ContextBuilder>,
        Key: CryptoKey,
        Output,
        ContextBuilder: EncryptionContextBuilder,
    > KeyDecryptable<Key, Option<Output>, ContextBuilder> for Option<T>
{
    fn decrypt_with_key(
        &self,
        key: &Key,
        context_builder: &ContextBuilder,
    ) -> Result<Option<Output>> {
        self.as_ref()
            .map(|e| e.decrypt_with_key(key, context_builder))
            .transpose()
    }
}

impl<
        T: KeyEncryptable<Key, Output, Context>,
        Key: CryptoKey,
        Output,
        Context: EncryptionContext,
    > KeyEncryptable<Key, Output, Context> for Box<T>
{
    fn encrypt_with_key(self, key: &Key, context: &Context) -> Result<Output> {
        (*self).encrypt_with_key(key, context)
    }
}

impl<
        T: KeyDecryptable<Key, Output, ContextBuilder>,
        Key: CryptoKey,
        Output,
        ContextBuilder: EncryptionContextBuilder,
    > KeyDecryptable<Key, Output, ContextBuilder> for Box<T>
{
    fn decrypt_with_key(&self, key: &Key, context_builder: &ContextBuilder) -> Result<Output> {
        (**self).decrypt_with_key(key, context_builder)
    }
}

impl<
        T: KeyEncryptable<Key, Output, Context> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        Context: EncryptionContext + Send + Sync,
    > KeyEncryptable<Key, Vec<Output>, Context> for Vec<T>
{
    fn encrypt_with_key(self, key: &Key, context: &Context) -> Result<Vec<Output>> {
        self.into_par_iter()
            .map(|e| e.encrypt_with_key(key, context))
            .collect()
    }
}

impl<
        T: KeyDecryptable<Key, Output, ContextBuilder> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        ContextBuilder: EncryptionContextBuilder + Send + Sync,
    > KeyDecryptable<Key, Vec<Output>, ContextBuilder> for Vec<T>
{
    fn decrypt_with_key(&self, key: &Key, context_builder: &ContextBuilder) -> Result<Vec<Output>> {
        self.into_par_iter()
            .map(|e| e.decrypt_with_key(key, context_builder))
            .collect()
    }
}

impl<
        T: KeyEncryptable<Key, Output, Context> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        Context: EncryptionContext + Send + Sync,
        Id: Hash + Eq + Send + Sync,
    > KeyEncryptable<Key, HashMap<Id, Output>, Context> for HashMap<Id, T>
{
    fn encrypt_with_key(self, key: &Key, context: &Context) -> Result<HashMap<Id, Output>> {
        self.into_par_iter()
            .map(|(id, e)| Ok((id, e.encrypt_with_key(key, context)?)))
            .collect()
    }
}

impl<
        T: KeyDecryptable<Key, Output, ContextBuilder> + Send + Sync,
        Key: CryptoKey + Send + Sync,
        Output: Send + Sync,
        Id: Hash + Eq + Copy + Send + Sync,
        ContextBuilder: EncryptionContextBuilder + Send + Sync,
    > KeyDecryptable<Key, HashMap<Id, Output>, ContextBuilder> for HashMap<Id, T>
{
    fn decrypt_with_key(
        &self,
        key: &Key,
        context_builder: &ContextBuilder,
    ) -> Result<HashMap<Id, Output>> {
        self.into_par_iter()
            .map(|(id, e)| Ok((*id, e.decrypt_with_key(key, context_builder)?)))
            .collect()
    }
}
