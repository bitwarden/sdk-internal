//!
//! This module contains all the necessary parts to create an in-memory key store that can be used
//! to securely store key and use them for encryption/decryption operations.
//!
//! ## Organization
//!
//! ### Key Identifiers
//! To avoid having to pass key materials over the crate boundaries, the key store API uses key
//! identifiers in its API. These key identifiers are user-defined types that contain no key
//! material, and are used to uniquely identify each key in the store. The key store doesn't specify
//! how these traits should be implemented, but we recommend using `enums`, and we provide an
//! optional macro ([key_ids](crate::key_ids)) that makes it easier to define them.
//!
//! ### Key Store
//! [KeyStore] is a thread-safe in-memory key store and the main entry point for using this module.
//! It provides functionality to encrypt and decrypt data using the keys stored in the store. The
//! store is designed to be used by a single user and should not be shared between users.
//!
//! ### Key Store Context
//! From a [KeyStore], you can also create an instance of [KeyStoreContext], which initializes a
//! temporary context-local key store for encryption/decryption operations that require the use of
//! per-item keys (like cipher keys or send keys, for example). Any keys stored in the context-local
//! store will be cleared when the context is dropped.

use std::sync::{Arc, RwLock};

use rayon::{iter::Either, prelude::*};

use crate::{CompositeEncryptable, Decryptable, IdentifyKey, KeyId, KeyIds};

mod backend;
mod context;

use backend::{StoreBackend, create_store};
use context::GlobalKeys;
pub use context::KeyStoreContext;

mod key_rotation;
pub use key_rotation::*;

/// An in-memory key store that provides a safe and secure way to store keys and use them for
/// encryption/decryption operations. The store API is designed to work only on key identifiers
/// ([KeyId]). These identifiers are user-defined types that contain no key material, which means
/// the API users don't have to worry about accidentally leaking keys.
///
/// Each store is designed to be used by a single user and should not be shared between users, but
/// the store itself is thread safe and can be cloned to share between threads.
///
/// ```rust
/// # use bitwarden_crypto::*;
///
/// // We need to define our own key identifier types. We provide a macro to make this easier.
/// key_ids! {
///     #[symmetric]
///     pub enum SymmKeyId {
///         User,
///         #[local]
///         Local(&'static str)
///     }
///     #[asymmetric]
///     pub enum AsymmKeyId {
///         UserPrivate,
///     }
///     #[signing]
///     pub enum SigningKeyId {
///        UserSigning,
///     }
///     pub Ids => SymmKeyId, AsymmKeyId, SigningKeyId;
/// }
///
/// // Initialize the store and insert a test key
/// let store: KeyStore<Ids> = KeyStore::default();
///
/// #[allow(deprecated)]
/// store.context_mut().set_symmetric_key(SymmKeyId::User, SymmetricCryptoKey::make_aes256_cbc_hmac_key());
///
/// // Define some data that needs to be encrypted
/// struct Data(String);
/// impl IdentifyKey<SymmKeyId> for Data {
///    fn key_identifier(&self) -> SymmKeyId {
///        SymmKeyId::User
///    }
/// }
/// impl CompositeEncryptable<Ids, SymmKeyId, EncString> for Data {
///     fn encrypt_composite(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeyId) -> Result<EncString, CryptoError> {
///         self.0.encrypt(ctx, key)
///     }
/// }
///
/// // Encrypt the data
/// let decrypted = Data("Hello, World!".to_string());
/// let encrypted = store.encrypt(decrypted).unwrap();
/// ```
#[derive(Clone)]
pub struct KeyStore<Ids: KeyIds> {
    // We use an Arc<> to make it easier to pass this store around, as we can
    // clone it instead of passing references
    inner: Arc<RwLock<KeyStoreInner<Ids>>>,
}

/// [KeyStore] contains sensitive data, provide a dummy [Debug] implementation.
impl<Ids: KeyIds> std::fmt::Debug for KeyStore<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish()
    }
}

struct KeyStoreInner<Ids: KeyIds> {
    symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    asymmetric_keys: Box<dyn StoreBackend<Ids::Asymmetric>>,
    signing_keys: Box<dyn StoreBackend<Ids::Signing>>,
}

/// Create a new key store with the best available implementation for the current platform.
impl<Ids: KeyIds> Default for KeyStore<Ids> {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeyStoreInner {
                symmetric_keys: create_store(),
                asymmetric_keys: create_store(),
                signing_keys: create_store(),
            })),
        }
    }
}

impl<Ids: KeyIds> KeyStore<Ids> {
    /// Clear all keys from the store. This can be used to clear all keys from memory in case of
    /// lock/logout, and is equivalent to destroying the store and creating a new one.
    pub fn clear(&self) {
        let mut keys = self.inner.write().expect("RwLock is poisoned");
        keys.symmetric_keys.clear();
        keys.asymmetric_keys.clear();
        keys.signing_keys.clear();
    }

    /// Initiate an encryption/decryption context. This context will have read only access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared when the context is dropped.
    ///
    /// If you are only looking to encrypt or decrypt items, you should implement
    /// [CompositeEncryptable]/[Decryptable] and use the [KeyStore::encrypt], [KeyStore::decrypt],
    /// [KeyStore::encrypt_list] and [KeyStore::decrypt_list] methods instead.
    ///
    /// The current implementation of context only clears the keys automatically when the context is
    /// dropped, and not between operations. This means that if you are using the same context
    /// for multiple operations, you may want to clear it manually between them. If possible, we
    /// recommend using [KeyStore::encrypt_list] and [KeyStore::decrypt_list] instead.
    ///
    /// [KeyStoreContext] is not [Send] or [Sync] and should not be shared between threads. Note
    /// that this can also be problematic in async code, and you should take care to ensure that
    /// you're not holding references to the context across await points, as that would cause the
    /// future to also not be [Send].
    ///
    /// Some other possible use cases for this API and alternative recommendations are:
    /// - Decrypting or encrypting multiple [Decryptable] or [CompositeEncryptable] items while
    ///   sharing any local keys. This is not recommended as it can lead to fragile and flaky
    ///   decryption/encryption operations. We recommend any local keys to be used only in the
    ///   context of a single [CompositeEncryptable] or [Decryptable] implementation. In the future
    ///   we might enforce this.
    /// - Obtaining the key material directly. We strongly recommend against doing this as it can
    ///   lead to key material being leaked, but we need to support it for backwards compatibility.
    ///   If you want to access the key material to encrypt it or derive a new key from it, we
    ///   provide functions for that:
    ///     - [KeyStoreContext::wrap_symmetric_key]
    ///     - [KeyStoreContext::encapsulate_key_unsigned]
    ///     - [KeyStoreContext::derive_shareable_key]
    pub fn context(&'_ self) -> KeyStoreContext<'_, Ids> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadOnly(self.inner.read().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            local_signing_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// <div class="warning">
    /// This is an advanced API, use with care and ONLY when needing to modify the global keys.
    ///
    /// The same pitfalls as [Self::context] apply here, but with the added risk of accidentally
    /// modifying the global keys and leaving the store in an inconsistent state.
    /// If you still need to use it, make sure you read this documentation to understand how to use
    /// it safely. </div>
    ///
    /// Initiate an encryption/decryption context. This context will have MUTABLE access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared up when the context is dropped.
    ///
    /// The only supported use case for this API is initializing the store with the user's symetric
    /// and private keys, and setting the organization keys. This method will be marked as
    /// `pub(crate)` in the future, once we have a safe API for key initialization and updating.
    ///
    /// [KeyStoreContext] is not [Send] or [Sync] and should not be shared between threads. Note
    /// that this can also be problematic in async code, and you should take care to ensure that
    /// you're not holding references to the context across await points, as that would cause the
    /// future to also not be [Send].
    pub fn context_mut(&'_ self) -> KeyStoreContext<'_, Ids> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadWrite(self.inner.write().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            local_signing_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Decript a single item using this key store. The key returned by `data.key_identifier()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item decryption.
    /// If you need to decrypt multiple items, use `decrypt_list` instead.
    pub fn decrypt<Key: KeyId, Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key>, Output>(
        &self,
        data: &Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.key_identifier();
        data.decrypt(&mut self.context(), key)
    }

    /// Encrypt a single item using this key store. The key returned by `data.key_identifier()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item encryption.
    /// If you need to encrypt multiple items, use `encrypt_list` instead.
    pub fn encrypt<
        Key: KeyId,
        Data: CompositeEncryptable<Ids, Key, Output> + IdentifyKey<Key>,
        Output,
    >(
        &self,
        data: Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.key_identifier();
        data.encrypt_composite(&mut self.context(), key)
    }

    /// Decrypt a list of items using this key store. The keys returned by
    /// `data[i].key_identifier()` must already be present in the store, otherwise this will
    /// return an error. This method will try to parallelize the decryption of the items, for
    /// better performance on large lists.
    pub fn decrypt_list<
        Key: KeyId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync,
        Output: Send + Sync,
    >(
        &self,
        data: &[Data],
    ) -> Result<Vec<Output>, crate::CryptoError> {
        let res: Result<Vec<_>, _> = data
            .par_chunks(batch_chunk_size(data.len()))
            .map(|chunk| {
                let mut ctx = self.context();

                let mut result = Vec::with_capacity(chunk.len());

                for item in chunk {
                    let key = item.key_identifier();
                    result.push(item.decrypt(&mut ctx, key));
                    ctx.clear_local();
                }

                result
            })
            .flatten()
            .collect();

        res
    }

    /// Decrypt a list of items using this key store, returning a tuple of successful and failed
    /// items.
    ///
    /// # Arguments
    /// * `data` - The list of items to decrypt.
    ///
    /// # Returns
    /// A tuple containing two vectors: the first vector contains the successfully decrypted items,
    /// and the second vector contains the original items that failed to decrypt.
    pub fn decrypt_list_with_failures<
        'a,
        Key: KeyId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync + 'a,
        Output: Send + Sync,
    >(
        &self,
        data: &'a [Data],
    ) -> (Vec<Output>, Vec<&'a Data>) {
        let results: (Vec<_>, Vec<_>) = data
            .par_chunks(batch_chunk_size(data.len()))
            .flat_map(|chunk| {
                let mut ctx = self.context();

                chunk
                    .iter()
                    .map(|item| {
                        let result = item
                            .decrypt(&mut ctx, item.key_identifier())
                            .map_err(|_| item);
                        ctx.clear_local();
                        result
                    })
                    .collect::<Vec<_>>()
            })
            .partition_map(|result| match result {
                Ok(output) => Either::Left(output),
                Err(original_item) => Either::Right(original_item),
            });

        results
    }

    /// Encrypt a list of items using this key store. The keys returned by
    /// `data[i].key_identifier()` must already be present in the store, otherwise this will
    /// return an error. This method will try to parallelize the encryption of the items, for
    /// better performance on large lists. This method is not parallelized, and is meant for
    /// single item encryption.
    pub fn encrypt_list<
        Key: KeyId,
        Data: CompositeEncryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync,
        Output: Send + Sync,
    >(
        &self,
        data: &[Data],
    ) -> Result<Vec<Output>, crate::CryptoError> {
        let res: Result<Vec<_>, _> = data
            .par_chunks(batch_chunk_size(data.len()))
            .map(|chunk| {
                let mut ctx = self.context();

                let mut result = Vec::with_capacity(chunk.len());

                for item in chunk {
                    let key = item.key_identifier();
                    result.push(item.encrypt_composite(&mut ctx, key));
                    ctx.clear_local();
                }

                result
            })
            .flatten()
            .collect();

        res
    }
}

/// Calculate the optimal chunk size for parallelizing encryption/decryption operations.
fn batch_chunk_size(len: usize) -> usize {
    // In an optimal scenario with no overhead, we would split the data evenly between
    // all available threads, rounding up to the nearest integer.
    let items_per_thread = usize::div_ceil(len, rayon::current_num_threads());

    // Because the addition of each chunk has some overhead (e.g. creating a new context, thread
    // synchronization), we want to split the data into chunks that are large enough to amortize
    // this overhead, but not too large that we get no benefit from multithreading. We've chosen
    // a value more or less arbitrarily, but it seems to work well in practice.
    const MINIMUM_CHUNK_SIZE: usize = 50;

    // As a result, we pick whichever of the two values is larger.
    usize::max(items_per_thread, MINIMUM_CHUNK_SIZE)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        EncString, PrimitiveEncryptable, SymmetricCryptoKey,
        store::{KeyStore, KeyStoreContext},
        traits::tests::{TestIds, TestSymmKey},
    };

    pub struct DataView(pub String, pub TestSymmKey);
    pub struct Data(pub EncString, pub TestSymmKey);

    impl crate::IdentifyKey<TestSymmKey> for DataView {
        fn key_identifier(&self) -> TestSymmKey {
            self.1
        }
    }

    impl crate::IdentifyKey<TestSymmKey> for Data {
        fn key_identifier(&self) -> TestSymmKey {
            self.1
        }
    }

    impl crate::CompositeEncryptable<TestIds, TestSymmKey, Data> for DataView {
        fn encrypt_composite(
            &self,
            ctx: &mut KeyStoreContext<TestIds>,
            key: TestSymmKey,
        ) -> Result<Data, crate::CryptoError> {
            Ok(Data(self.0.encrypt(ctx, key)?, key))
        }
    }

    impl crate::Decryptable<TestIds, TestSymmKey, DataView> for Data {
        fn decrypt(
            &self,
            ctx: &mut KeyStoreContext<TestIds>,
            key: TestSymmKey,
        ) -> Result<DataView, crate::CryptoError> {
            Ok(DataView(self.0.decrypt(ctx, key)?, key))
        }
    }

    #[test]
    fn test_multithread_decrypt_keeps_order() {
        let store: KeyStore<TestIds> = KeyStore::default();

        // Create a bunch of random keys
        for n in 0..15 {
            #[allow(deprecated)]
            store
                .context_mut()
                .set_symmetric_key(
                    TestSymmKey::A(n),
                    SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
                )
                .unwrap();
        }

        // Create some test data
        let data: Vec<_> = (0..300usize)
            .map(|n| DataView(format!("Test {n}"), TestSymmKey::A((n % 15) as u8)))
            .collect();

        // Encrypt the data
        let encrypted: Vec<_> = store.encrypt_list(&data).unwrap();

        // Decrypt the data
        let decrypted: Vec<_> = store.decrypt_list(&encrypted).unwrap();

        // Check that the data is the same, and in the same order as the original
        for (orig, dec) in data.iter().zip(decrypted.iter()) {
            assert_eq!(orig.0, dec.0);
            assert_eq!(orig.1, dec.1);
        }
    }
}
