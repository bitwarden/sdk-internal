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
//! optional macro ([key_slot_ids](crate::key_slot_ids)) that makes it easier to define them.
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

use rayon::prelude::*;

use crate::{CompositeEncryptable, Decryptable, IdentifyKey, KeySlotId, KeySlotIds};

mod backend;
mod cipher_suite;
mod context;

use backend::{StoreBackend, create_store};
pub use cipher_suite::CipherSuite;
use context::GlobalKeys;
pub use context::KeyStoreContext;

/// An in-memory key store that provides a safe and secure way to store keys and use them for
/// encryption/decryption operations. The store API is designed to work only on key identifiers
/// ([KeySlotId]). These identifiers are user-defined types that contain no key material, which
/// means the API users don't have to worry about accidentally leaking keys.
///
/// Each store is designed to be used by a single user and should not be shared between users, but
/// the store itself is thread safe and can be cloned to share between threads.
///
/// ```rust
/// # use bitwarden_crypto::*;
///
/// // We need to define our own key identifier types. We provide a macro to make this easier.
/// key_slot_ids! {
///     #[symmetric]
///     pub enum SymmKeySlotIds {
///         User,
///         #[local]
///         Local(LocalId),
///     }
///     #[private]
///     pub enum PrivateKeySlotIds {
///         UserPrivate,
///         #[local]
///         Local(LocalId),
///     }
///     #[signing]
///     pub enum SigningKeySlotIds {
///        UserSigning,
///        #[local]
///        Local(LocalId),
///     }
///     pub Ids => SymmKeySlotIds, PrivateKeySlotIds, SigningKeySlotIds;
/// }
///
/// // Initialize the store and insert a test key
/// let store: KeyStore<Ids> = KeyStore::default();
///
/// #[allow(deprecated)]
/// store.context_mut().set_symmetric_key(SymmKeySlotIds::User, SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac));
///
/// // Define some data that needs to be encrypted
/// struct Data(String);
/// impl IdentifyKey<SymmKeySlotIds> for Data {
///    fn key_identifier(&self) -> SymmKeySlotIds {
///        SymmKeySlotIds::User
///    }
/// }
/// impl CompositeEncryptable<Ids, SymmKeySlotIds, EncString> for Data {
///     fn encrypt_composite(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeySlotIds) -> Result<EncString, CryptoError> {
///         self.0.encrypt(ctx, key)
///     }
/// }
///
/// // Encrypt the data
/// let decrypted = Data("Hello, World!".to_string());
/// let encrypted = store.encrypt(decrypted).unwrap();
/// ```
pub struct KeyStore<Ids: KeySlotIds> {
    // We use an Arc<> to make it easier to pass this store around, as we can
    // clone it instead of passing references
    inner: Arc<RwLock<KeyStoreInner<Ids>>>,
}

// Manually implement Clone to avoid requiring Ids: Clone
impl<Ids: KeySlotIds> Clone for KeyStore<Ids> {
    fn clone(&self) -> Self {
        KeyStore {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// [KeyStore] contains sensitive data, provide a dummy [Debug] implementation.
impl<Ids: KeySlotIds> std::fmt::Debug for KeyStore<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish()
    }
}

struct KeyStoreInner<Ids: KeySlotIds> {
    symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    private_keys: Box<dyn StoreBackend<Ids::Private>>,
    signing_keys: Box<dyn StoreBackend<Ids::Signing>>,
    security_state_version: u64,
    cipher_suite: CipherSuite,
}

/// Create a new key store with the best available implementation for the current platform.
impl<Ids: KeySlotIds> Default for KeyStore<Ids> {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeyStoreInner {
                symmetric_keys: create_store(),
                private_keys: create_store(),
                signing_keys: create_store(),
                security_state_version: 1,
                cipher_suite: CipherSuite::default(),
            })),
        }
    }
}

impl<Ids: KeySlotIds> KeyStore<Ids> {
    /// Clear all keys from the store. This can be used to clear all keys from memory in case of
    /// lock/logout, and is equivalent to destroying the store and creating a new one.
    pub fn clear(&self) {
        let mut keys = self.inner.write().expect("RwLock is poisoned");
        keys.symmetric_keys.clear();
        keys.private_keys.clear();
        keys.signing_keys.clear();
    }

    /// Sets the security state version for this store.
    pub fn set_security_state_version(&self, version: u64) {
        let mut data = self.inner.write().expect("RwLock is poisoned");
        data.security_state_version = version;
    }

    /// Sets the [CipherSuite] for this store, which determines the algorithms operations are
    /// allowed to use (e.g. the KDF for a new account). This should be set once when the store
    /// is constructed, based on the client's environment.
    pub fn set_cipher_suite(&self, cipher_suite: CipherSuite) {
        let mut data = self.inner.write().expect("RwLock is poisoned");
        data.cipher_suite = cipher_suite;
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
    ///     - [KeyStoreContext::derive_shareable_key]
    pub fn context(&'_ self) -> KeyStoreContext<'_, Ids> {
        let data = self.inner.read().expect("RwLock is poisoned");
        let security_state_version = data.security_state_version;
        let cipher_suite = data.cipher_suite;
        KeyStoreContext {
            global_keys: GlobalKeys::ReadOnly(data),
            local_symmetric_keys: create_store(),
            local_private_keys: create_store(),
            local_signing_keys: create_store(),
            security_state_version,
            cipher_suite,
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
        let inner = self.inner.write().expect("RwLock is poisoned");
        let security_state_version = inner.security_state_version;
        let cipher_suite = inner.cipher_suite;
        KeyStoreContext {
            global_keys: GlobalKeys::ReadWrite(inner),
            local_symmetric_keys: create_store(),
            local_private_keys: create_store(),
            local_signing_keys: create_store(),
            security_state_version,
            cipher_suite,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Decript a single item using this key store. The key returned by `data.key_identifier()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item decryption.
    /// If you need to decrypt multiple items, use `decrypt_list` instead.
    pub fn decrypt<
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key>,
        Output,
    >(
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
        Key: KeySlotId,
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
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync,
        Output: Send + Sync,
    >(
        &self,
        data: &[Data],
    ) -> Result<Vec<Output>, crate::CryptoError> {
        self.decrypt_batch(data).into_iter().collect()
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
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync + 'a,
        Output: Send + Sync,
    >(
        &self,
        data: &'a [Data],
    ) -> (Vec<Output>, Vec<&'a Data>) {
        let mut successes = Vec::with_capacity(data.len());
        let mut failures = Vec::new();
        for (item, result) in data.iter().zip(self.decrypt_batch(data)) {
            match result {
                Ok(output) => successes.push(output),
                Err(_) => failures.push(item),
            }
        }
        (successes, failures)
    }

    /// Decrypt the items of an iterator using this key store, a batch at a time, yielding the
    /// results in input order. Meant for long lists whose items are produced as they are read,
    /// such as items converted from another language one by one, so that only one batch of input
    /// and output is held at a time. For items already in a slice, use
    /// [KeyStore::decrypt_list] or [KeyStore::decrypt_list_with_failures].
    ///
    /// Each input item is a `Result`, so that errors the caller meets while producing the items
    /// (for example, an item that does not convert) pass through in order. Each output item is:
    /// - `Ok(Ok(output))` for an item that decrypted,
    /// - `Ok(Err(failure))` for an item that failed to decrypt, handing back the item and its
    ///   error. The pair is boxed so that a result takes the size of the output, not of the
    ///   encrypted item, which can be much larger.
    /// - `Err(error)` for an input error, in the place where the input yielded it.
    ///
    /// The iterator does not stop at an input error: it goes on with the input items after it. A
    /// caller that fails on the first input error stops reading there, and the input is not read
    /// further. Items are read from the input one batch at a time, and a batch ends early at an
    /// input error, so the error is yielded right after the items before it.
    ///
    /// The batch size depends on the number of threads available. Each batch is decrypted by the
    /// same code as [KeyStore::decrypt_list] and [KeyStore::decrypt_list_with_failures], which
    /// spreads the items over the available threads, with one context per thread's share, cleared
    /// after each item. No context is held between batches, so a caller that reads the iterator
    /// slowly does not keep the store locked.
    pub fn decrypt_iter<'a, Key, Data, Output, E>(
        &'a self,
        items: impl IntoIterator<Item = Result<Data, E>> + 'a,
    ) -> impl Iterator<Item = Result<Result<Output, Box<(Data, crate::CryptoError)>>, E>> + 'a
    where
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Sync + 'a,
        Output: Send + 'a,
        E: 'a,
    {
        self.decrypt_iter_in_batches(items, decrypt_iter_batch_size())
    }

    /// [KeyStore::decrypt_iter] with a given batch size (at least one).
    fn decrypt_iter_in_batches<'a, Key, Data, Output, E>(
        &'a self,
        items: impl IntoIterator<Item = Result<Data, E>> + 'a,
        batch_size: usize,
    ) -> impl Iterator<Item = Result<Result<Output, Box<(Data, crate::CryptoError)>>, E>> + 'a
    where
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Sync + 'a,
        Output: Send + 'a,
        E: 'a,
    {
        DecryptBatches {
            store: self,
            items: items.into_iter(),
            batch_size: batch_size.max(1),
            batch: Vec::new().into_iter(),
            results: Vec::new().into_iter(),
            input_error: None,
            _key: std::marker::PhantomData,
        }
    }

    /// Decrypts the items of a slice, returning each item's result in order. The decrypt behind
    /// [KeyStore::decrypt_list], [KeyStore::decrypt_list_with_failures], and each batch of
    /// [KeyStore::decrypt_iter].
    ///
    /// The items are split into chunks spread over the rayon threads. Each chunk gets its own
    /// context, whose local keys are cleared after every item, and the context is dropped at the
    /// end of the chunk.
    fn decrypt_batch<Key, Data, Output>(
        &self,
        batch: &[Data],
    ) -> Vec<Result<Output, crate::CryptoError>>
    where
        Key: KeySlotId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Sync,
        Output: Send,
    {
        batch
            .par_chunks(batch_chunk_size(batch.len()))
            .flat_map_iter(|chunk| {
                let mut ctx = self.context();

                chunk
                    .iter()
                    .map(|item| {
                        let result = item.decrypt(&mut ctx, item.key_identifier());
                        ctx.clear_local();
                        result
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Encrypt a list of items using this key store. The keys returned by
    /// `data[i].key_identifier()` must already be present in the store, otherwise this will
    /// return an error. This method will try to parallelize the encryption of the items, for
    /// better performance on large lists. This method is not parallelized, and is meant for
    /// single item encryption.
    pub fn encrypt_list<
        Key: KeySlotId,
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

/// How many items [KeyStore::decrypt_iter] reads and decrypts at a time.
fn decrypt_iter_batch_size() -> usize {
    // The batch has to be large enough to give every thread a share well above the minimum chunk
    // size of `batch_chunk_size`, so that the per-batch cost of spreading the work over the threads
    // and waiting for the slowest one stays small. It has to be small enough that one batch of
    // input and output takes little memory: in WASM, which has a single thread and whose memory
    // never shrinks, this is 250 items. A caller reading the items out of a `Vec` holds the batch
    // on top of the `Vec`, which keeps its buffer until it is dropped.
    const ITEMS_PER_THREAD: usize = 250;

    rayon::current_num_threads() * ITEMS_PER_THREAD
}

/// The iterator [KeyStore::decrypt_iter] returns.
struct DecryptBatches<'a, Ids: KeySlotIds, Key, Items, Data, Output, E> {
    store: &'a KeyStore<Ids>,
    items: Items,
    batch_size: usize,
    /// The rest of the current batch's items, each handed back if it failed to decrypt.
    batch: std::vec::IntoIter<Data>,
    /// The results of the rest of the current batch's items, in the same order.
    results: std::vec::IntoIter<Result<Output, crate::CryptoError>>,
    /// An input error that ended the current batch, yielded after the batch's results.
    input_error: Option<E>,
    _key: std::marker::PhantomData<Key>,
}

impl<Ids, Key, Items, Data, Output, E> Iterator
    for DecryptBatches<'_, Ids, Key, Items, Data, Output, E>
where
    Ids: KeySlotIds,
    Key: KeySlotId,
    Items: Iterator<Item = Result<Data, E>>,
    Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Sync,
    Output: Send,
{
    type Item = Result<Result<Output, Box<(Data, crate::CryptoError)>>, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if let (Some(item), Some(result)) = (self.batch.next(), self.results.next()) {
            return Some(Ok(result.map_err(|error| Box::new((item, error)))));
        }
        if let Some(error) = self.input_error.take() {
            return Some(Err(error));
        }

        // Release the previous batch's buffers before reading the next batch.
        self.batch = Vec::new().into_iter();
        self.results = Vec::new().into_iter();

        let capacity = match self.items.size_hint() {
            (_, Some(upper)) => upper.min(self.batch_size),
            (_, None) => self.batch_size,
        };
        let mut batch = Vec::with_capacity(capacity);
        while batch.len() < self.batch_size {
            match self.items.next() {
                Some(Ok(item)) => batch.push(item),
                Some(Err(error)) => {
                    self.input_error = Some(error);
                    break;
                }
                None => break,
            }
        }

        if batch.is_empty() {
            return self.input_error.take().map(Err);
        }

        self.results = self.store.decrypt_batch(&batch).into_iter();
        self.batch = batch.into_iter();
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.results.len() + usize::from(self.input_error.is_some());
        let (lower, upper) = self.items.size_hint();
        (
            buffered.saturating_add(lower),
            upper.and_then(|upper| upper.checked_add(buffered)),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        EncString, PrimitiveEncryptable, SymmetricKeyAlgorithm,
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
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, TestSymmKey::A(n))
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

    mod decrypt_list {
        use super::{decrypt_iter::store_and_items, *};

        #[test]
        fn decrypt_list_fails_with_a_failing_item() {
            let (store, items) = store_and_items(120, &[70]);

            let result: Result<Vec<DataView>, _> = store.decrypt_list(&items);

            assert!(result.is_err());
        }

        #[test]
        fn decrypt_list_with_failures_keeps_the_order_of_each_side() {
            // More items than one chunk of `batch_chunk_size`, with failures in more than one
            // chunk.
            let failing = [0, 3, 60, 61, 119];
            let (store, items) = store_and_items(120, &failing);

            let (successes, failures): (Vec<DataView>, Vec<&Data>) =
                store.decrypt_list_with_failures(&items);

            let expected: Vec<_> = (0..120)
                .filter(|n| !failing.contains(n))
                .map(|n| format!("Item {n}"))
                .collect();
            let decrypted: Vec<_> = successes.into_iter().map(|view| view.0).collect();
            assert_eq!(decrypted, expected);
            let failed: Vec<_> = failures.into_iter().map(std::ptr::from_ref).collect();
            let expected_failed: Vec<_> = failing
                .iter()
                .map(|&n| std::ptr::from_ref(&items[n]))
                .collect();
            assert_eq!(failed, expected_failed);
        }
    }

    mod decrypt_iter {
        use std::cell::Cell;

        use super::*;
        use crate::{CryptoError, Decryptable, IdentifyKey, store::decrypt_iter_batch_size};

        /// A key slot no test puts a key in, so an item under it fails to decrypt.
        const MISSING_KEY: TestSymmKey = TestSymmKey::A(99);

        /// A store with a few keys, and `count` items encrypted under them, in order. The items at
        /// `failing` are put under [MISSING_KEY].
        pub(super) fn store_and_items(
            count: usize,
            failing: &[usize],
        ) -> (KeyStore<TestIds>, Vec<Data>) {
            let store: KeyStore<TestIds> = KeyStore::default();
            for n in 0..3 {
                let mut ctx = store.context_mut();
                let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
                ctx.persist_symmetric_key(local_key_id, TestSymmKey::A(n))
                    .unwrap();
            }
            let views: Vec<_> = (0..count)
                .map(|n| DataView(format!("Item {n}"), TestSymmKey::A((n % 3) as u8)))
                .collect();
            let items = store
                .encrypt_list(&views)
                .unwrap()
                .into_iter()
                .enumerate()
                .map(|(n, item)| {
                    if failing.contains(&n) {
                        Data(item.0, MISSING_KEY)
                    } else {
                        item
                    }
                })
                .collect();
            (store, items)
        }

        /// An output item of [KeyStore::decrypt_iter] in these tests.
        type DecryptIterItem = Result<Result<DataView, Box<(Data, CryptoError)>>, &'static str>;

        /// What an output item says, for comparing whole outputs: the decrypted text, the failed
        /// item's key, or the input error.
        #[derive(Debug, PartialEq)]
        enum Outcome {
            Decrypted(String),
            Failed(TestSymmKey),
            InputError(&'static str),
        }

        fn outcome(item: DecryptIterItem) -> Outcome {
            match item {
                Ok(Ok(view)) => Outcome::Decrypted(view.0),
                Ok(Err(failure)) => Outcome::Failed(failure.0.1),
                Err(error) => Outcome::InputError(error),
            }
        }

        fn decrypted(range: std::ops::Range<usize>) -> Vec<Outcome> {
            range
                .map(|n| Outcome::Decrypted(format!("Item {n}")))
                .collect()
        }

        #[test]
        fn yields_nothing_for_no_items() {
            let (store, _) = store_and_items(0, &[]);

            let output: Vec<_> = store
                .decrypt_iter::<_, Data, DataView, &str>(std::iter::empty())
                .collect();

            assert!(output.is_empty());
        }

        #[test]
        fn decrypts_in_order_with_the_default_batch_size() {
            let count = decrypt_iter_batch_size() * 2 + 7;
            let (store, items) = store_and_items(count, &[]);

            let output: Vec<_> = store
                .decrypt_iter(items.into_iter().map(Ok))
                .map(outcome)
                .collect();

            assert_eq!(output, decrypted(0..count));
        }

        #[test]
        fn decrypts_in_order_across_batch_sizes() {
            // Shorter than a batch, exactly a batch, and longer than a batch with a partial last
            // batch, for a batch size below and above the minimum chunk size.
            for batch_size in [1, 7, 100] {
                for count in [
                    1,
                    batch_size - 1,
                    batch_size,
                    batch_size + 1,
                    3 * batch_size + 2,
                ] {
                    if count == 0 {
                        continue;
                    }
                    let (store, items) = store_and_items(count, &[]);

                    let output: Vec<_> = store
                        .decrypt_iter_in_batches(items.into_iter().map(Ok::<_, &str>), batch_size)
                        .map(outcome)
                        .collect();

                    assert_eq!(
                        output,
                        decrypted(0..count),
                        "batch {batch_size}, {count} items"
                    );
                }
            }
        }

        #[test]
        fn hands_back_failed_items_in_place() {
            // Failures at the start, on both sides of the batch boundaries at 5 and 10, and at the
            // end.
            let (store, items) = store_and_items(12, &[0, 4, 5, 9, 10, 11]);

            let output: Vec<_> = store
                .decrypt_iter_in_batches(items.into_iter().map(Ok), 5)
                .map(outcome)
                .collect();

            let expected: Vec<_> = (0..12)
                .map(|n| {
                    if [0, 4, 5, 9, 10, 11].contains(&n) {
                        Outcome::Failed(MISSING_KEY)
                    } else {
                        Outcome::Decrypted(format!("Item {n}"))
                    }
                })
                .collect();
            assert_eq!(output, expected);
        }

        #[test]
        fn passes_input_errors_through_in_place_and_goes_on() {
            let (store, items) = store_and_items(8, &[]);
            // Input errors in the middle of a batch, right after a batch boundary, and last.
            let input: Vec<Result<Data, &str>> = items
                .into_iter()
                .enumerate()
                .flat_map(|(n, item)| match n {
                    2 => vec![Ok(item), Err("after 2")],
                    3 => vec![Err("before 3"), Ok(item)],
                    7 => vec![Ok(item), Err("last")],
                    _ => vec![Ok(item)],
                })
                .collect();

            let output: Vec<_> = store
                .decrypt_iter_in_batches(input, 3)
                .map(outcome)
                .collect();

            let mut expected = decrypted(0..3);
            expected.push(Outcome::InputError("after 2"));
            expected.push(Outcome::InputError("before 3"));
            expected.extend(decrypted(3..8));
            expected.push(Outcome::InputError("last"));
            assert_eq!(output, expected);
        }

        #[test]
        fn stops_reading_the_input_when_the_caller_stops_at_an_input_error() {
            let (store, items) = store_and_items(10, &[]);
            let read = Cell::new(0);
            let input = items.into_iter().enumerate().map(|(n, item)| {
                read.set(read.get() + 1);
                if n == 4 { Err("invalid") } else { Ok(item) }
            });

            let result: Result<Vec<_>, _> = store.decrypt_iter_in_batches(input, 3).collect();

            assert_eq!(result.err(), Some("invalid"));
            assert_eq!(read.get(), 5);
        }

        #[test]
        fn reads_the_input_one_batch_at_a_time() {
            let (store, items) = store_and_items(10, &[]);
            let read = Cell::new(0);
            let input = items.into_iter().map(|item| {
                read.set(read.get() + 1);
                Ok::<_, &str>(item)
            });

            let mut output = store.decrypt_iter_in_batches(input, 4);

            assert_eq!(
                read.get(),
                0,
                "nothing is read before the first item is asked for"
            );
            let mut read_after_each = Vec::new();
            while output.next().is_some() {
                read_after_each.push(read.get());
            }
            assert_eq!(read_after_each, [4, 4, 4, 4, 8, 8, 8, 8, 10, 10]);
        }

        #[test]
        fn holds_no_context_between_items() {
            let (store, items) = store_and_items(10, &[]);

            let mut output = store.decrypt_iter_in_batches(items.into_iter().map(Ok::<_, &str>), 4);

            // A context holds the store's lock, which would make the write lock unavailable.
            while output.next().is_some() {
                assert!(store.inner.try_write().is_ok());
            }
        }

        /// A wrapper with its own decryption, as a caller might map each input item into.
        struct Wrapped(Data);

        impl IdentifyKey<TestSymmKey> for Wrapped {
            fn key_identifier(&self) -> TestSymmKey {
                self.0.key_identifier()
            }
        }

        impl Decryptable<TestIds, TestSymmKey, DataView> for Wrapped {
            fn decrypt(
                &self,
                ctx: &mut KeyStoreContext<TestIds>,
                key: TestSymmKey,
            ) -> Result<DataView, CryptoError> {
                let view = self.0.decrypt(ctx, key)?;
                Ok(DataView(format!("Wrapped {}", view.0), view.1))
            }
        }

        #[test]
        fn decrypts_mapped_items_and_hands_back_the_mapped_item() {
            let (store, items) = store_and_items(5, &[3]);

            let output: Vec<_> = store
                .decrypt_iter_in_batches(
                    items.into_iter().map(|item| Ok::<_, &str>(Wrapped(item))),
                    2,
                )
                .map(|item| match item.unwrap() {
                    Ok(view) => Ok(view.0),
                    Err(failure) => Err((failure.0).0.1),
                })
                .collect();

            assert_eq!(
                output,
                [
                    Ok("Wrapped Item 0".to_owned()),
                    Ok("Wrapped Item 1".to_owned()),
                    Ok("Wrapped Item 2".to_owned()),
                    Err(MISSING_KEY),
                    Ok("Wrapped Item 4".to_owned()),
                ]
            );
        }
    }
}
