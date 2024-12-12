use std::sync::{Arc, RwLock};

use rayon::prelude::*;

use crate::{Decryptable, Encryptable, KeyRef, KeyRefs, UsesKey};

mod backend;
mod context;

pub use backend::create_store;
use backend::StoreBackend;
use context::GlobalKeys;
pub use context::KeyStoreContext;

/// An in-memory key store that provides a safe and secure way to store keys and use them for
/// encryption/decryption operations. The store API is designed to work only on key references
/// ([KeyRef]). These references are user-defined types that contain no key material, which means
/// the API users don't have to worry about accidentally leaking keys.
///
/// Each store is designed to be used by a single user and should not be shared between users, but
/// the store itself is thread safe and can be cloned to share between threads.
///
/// ```rust
/// use bitwarden_crypto::{*, store::*};
///
/// // We need to define our own key reference types. We provide a macro to make this easier.
/// key_refs! {
///     #[symmetric]
///     pub enum SymmKeyRef {
///         User,
///         #[local]
///         Local(&'static str)
///     }
///     #[asymmetric]
///     pub enum AsymmKeyRef {
///         UserPrivate,
///     }
///     pub Refs => SymmKeyRef, AsymmKeyRef;
/// }
///
/// // Initialize the store and insert a test key
/// let store: KeyStore<Refs> = KeyStore::new();
///
/// #[allow(deprecated)]
/// store.context_mut().set_symmetric_key(SymmKeyRef::User, SymmetricCryptoKey::generate(rand::thread_rng()));
///
/// // Define some data that needs to be encrypted
/// struct Data(String);
/// impl UsesKey<SymmKeyRef> for Data {
///    fn uses_key(&self) -> SymmKeyRef {
///        SymmKeyRef::User
///    }
/// }
/// impl Encryptable<Refs, SymmKeyRef, EncString> for Data {
///     fn encrypt(&self, ctx: &mut KeyStoreContext<Refs>, key: SymmKeyRef) -> Result<EncString, CryptoError> {
///         self.0.encrypt(ctx, key)
///     }
/// }
///
/// // Encrypt the data
/// let decrypted = Data("Hello, World!".to_string());
/// let encrypted = store.encrypt(decrypted).unwrap();
/// ```
#[derive(Clone)]
pub struct KeyStore<Refs: KeyRefs> {
    // We use an Arc<> to make it easier to pass this store around, as we can
    // clone it instead of passing references
    inner: Arc<RwLock<KeyStoreInner<Refs>>>,
}

impl<Refs: KeyRefs> std::fmt::Debug for KeyStore<Refs> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish()
    }
}

struct KeyStoreInner<Refs: KeyRefs> {
    symmetric_keys: Box<dyn StoreBackend<Refs::Symmetric>>,
    asymmetric_keys: Box<dyn StoreBackend<Refs::Asymmetric>>,
}

impl<Refs: KeyRefs> KeyStore<Refs> {
    /// Create a new key store with the best available implementation for the current platform.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeyStoreInner {
                symmetric_keys: create_store(),
                asymmetric_keys: create_store(),
            })),
        }
    }

    /// Clear all keys from the store. This can be used to clear all keys from memory in case of
    /// lock/logout, and is equivalent to destroying the store and creating a new one.
    pub fn clear(&self) {
        let mut keys = self.inner.write().expect("RwLock is poisoned");
        keys.symmetric_keys.clear();
        keys.asymmetric_keys.clear();
    }

    /// Initiate an encryption/decryption context. This context will have read only access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared up when the context is dropped.
    ///
    /// This is an advanced API, use with care. Prefer to instead use
    /// `encrypt`/`decrypt`/`encrypt_list`/`decrypt_list` methods.
    ///
    /// One of the pitfalls of the current implementations is that keys stored in the context-local
    /// store only get cleared automatically when the context is dropped, and not between
    /// operations. This means that if you are using the same context for multiple operations,
    /// you may want to clear it manually between them.
    pub fn context(&'_ self) -> KeyStoreContext<'_, Refs> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadOnly(self.inner.read().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Initiate an encryption/decryption context. This context will have MUTABLE access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared up when the context is dropped.
    ///
    /// This is an advanced API, use with care and ONLY when needing to modify the global keys.
    ///
    /// The same pitfalls as `context` apply here, but with the added risk of accidentally
    /// modifying the global keys and leaving the store in an inconsistent state.
    ///
    /// TODO: We should work towards making this pub(crate), and instead providing a safe API for
    /// modifying the global keys. (i.e. `derive_master_key`, `derive_user_key`, etc.)
    pub fn context_mut(&'_ self) -> KeyStoreContext<'_, Refs> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadWrite(self.inner.write().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Decript a single item using this key store. The key returned by `data.uses_key()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item decryption.
    /// If you need to decrypt multiple items, use `decrypt_list` instead.
    pub fn decrypt<Key: KeyRef, Data: Decryptable<Refs, Key, Output> + UsesKey<Key>, Output>(
        &self,
        data: &Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.uses_key();
        data.decrypt(&mut self.context(), key)
    }

    /// Encrypt a single item using this key store. The key returned by `data.uses_key()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item encryption.
    /// If you need to encrypt multiple items, use `encrypt_list` instead.
    pub fn encrypt<Key: KeyRef, Data: Encryptable<Refs, Key, Output> + UsesKey<Key>, Output>(
        &self,
        data: Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.uses_key();
        data.encrypt(&mut self.context(), key)
    }

    /// Decrypt a list of items using this key store. The keys returned by `data[i].uses_key()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method will try to parallelize the decryption of the items, for better performance on
    /// large lists.
    pub fn decrypt_list<
        Key: KeyRef,
        Data: Decryptable<Refs, Key, Output> + UsesKey<Key> + Send + Sync,
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
                    let key = item.uses_key();
                    result.push(item.decrypt(&mut ctx, key));
                    ctx.clear();
                }

                result
            })
            .flatten()
            .collect();

        res
    }

    /// Encrypt a list of items using this key store. The keys returned by `data[i].uses_key()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method will try to parallelize the encryption of the items, for better performance on
    /// large lists. This method is not parallelized, and is meant for single item encryption.
    pub fn encrypt_list<
        Key: KeyRef,
        Data: Encryptable<Refs, Key, Output> + UsesKey<Key> + Send + Sync,
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
                    let key = item.uses_key();
                    result.push(item.encrypt(&mut ctx, key));
                    ctx.clear();
                }

                result
            })
            .flatten()
            .collect();

        res
    }
}

fn batch_chunk_size(len: usize) -> usize {
    // We want to split all the data between available threads, but at the
    // same time we don't want to split it too much if the amount of data is small.

    // In this case, the minimum chunk size is 50. This was chosen pretty arbitrarily,
    // but it seems to work well in practice.
    usize::max(1 + len / rayon::current_num_threads(), 50)
}
