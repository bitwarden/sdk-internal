//! Streaming cipher decryption for JavaScript.
//!
//! WASM linear memory grows to the largest single call and never shrinks. Decrypting a whole vault
//! in one call holds every encrypted and decrypted cipher at once, and that peak stays reserved for
//! the rest of the session. [`CiphersClient::decrypt_list_iterable`] pulls encrypted ciphers from a
//! JavaScript `AsyncCipherSource` a chunk at a time and returns the results as an
//! `AsyncIterable`, so linear memory only holds the chunk being decrypted.
//!
//! [`CipherDecryptStream`] and [`CipherAsyncDecryptStream`] expose the same pulls as explicit
//! `next_item` / `next_chunk` calls. They are baselines for the performance harnesses in
//! `bitwarden-wasm-internal/integration-tests/perf`, which compare them with the iterable.

use bitwarden_core::{
    Client,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{Decryptable, IdentifyKey, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_ffi::BwStream;
use futures::{StreamExt, stream};
use thiserror::Error;
use tsify::Tsify;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{
    JsFuture,
    js_sys::{Array, Promise},
};

use super::CiphersClient;
use crate::{Cipher, CipherListView, cipher::cipher::StrictDecrypt};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Supplies encrypted ciphers to `CiphersClient.decrypt_list_iterable`, a chunk at a time.
 */
export interface AsyncCipherSource {
    /**
     * Resolves to the next ciphers, at most `max` of them. An empty array is allowed and skipped.
     *
     * @returns `undefined` once every cipher has been returned.
     */
    nextChunk(max: number): Promise<Cipher[] | undefined>;
}

/**
 * Supplies encrypted ciphers to a `CipherDecryptStream`, a chunk at a time.
 */
export interface CipherSource {
    /**
     * Returns the next ciphers, at most `max` of them. An empty array is allowed and skipped.
     *
     * @returns `undefined` once every cipher has been returned.
     */
    nextChunk(max: number): Cipher[] | undefined;
}
"#;

#[bitwarden_ffi::wasm_import]
extern "C" {
    /// The JavaScript object implementing `AsyncCipherSource`.
    #[wasm_bindgen(js_name = AsyncCipherSource, typescript_type = "AsyncCipherSource")]
    pub type RawJsAsyncCipherSource;

    // Imported as a sync call that returns the Promise: an `async fn` import with `catch` only
    // catches a rejection, not a synchronous throw.
    #[wasm_bindgen(catch, method, structural, js_name = nextChunk)]
    fn next_chunk(this: &RawJsAsyncCipherSource, max: u32) -> Result<JsValue, JsValue>;

    /// The JavaScript object implementing `CipherSource`.
    #[wasm_bindgen(js_name = CipherSource, typescript_type = "CipherSource")]
    pub type RawJsCipherSource;

    #[wasm_bindgen(catch, method, structural, js_name = nextChunk)]
    fn next_chunk(this: &RawJsCipherSource, max: u32) -> Result<Option<Vec<Cipher>>, JsValue>;
}

/// Ends a cipher stream, as opposed to a single cipher that fails to decrypt.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptStreamError {
    /// The user key is not in the key store, so no cipher can decrypt.
    #[error("The vault is locked")]
    VaultLocked,
}

/// A cipher that failed to decrypt crosses to JavaScript as the plain `Cipher`. It is boxed on the
/// Rust side because a [`Cipher`] is over ten times the size of a [`CipherListView`], and a chunk
/// of results is a vector of the larger of the two.
impl From<Box<Cipher>> for JsValue {
    fn from(cipher: Box<Cipher>) -> Self {
        (*cipher).into()
    }
}

#[bitwarden_ffi::wasm_export]
impl CiphersClient {
    /// Decrypts the ciphers `source` supplies, pulling up to `chunk_size` at a time (at least
    /// one), and returns them as an `AsyncIterable` in source order.
    ///
    /// Each cipher arrives as `{ ok: true, value }` with its [`CipherListView`], or as
    /// `{ ok: false, error }` with the encrypted [`Cipher`] when it fails to decrypt. A failure
    /// specific to the stream ends the iteration instead: the iterator's `next()` rejects once and
    /// later calls return done. That happens when `nextChunk` throws or rejects (with what it
    /// threw), and with [`DecryptStreamError::VaultLocked`] when the user key is gone when a chunk
    /// is decrypted, as after locking. Breaking out of a `for await` stops pulling from `source`.
    ///
    /// Strict decryption is decided by the feature flags when the first chunk is pulled.
    #[wasm_bindgen(unchecked_return_type = "AsyncIterable<BwResult<CipherListView, Cipher>>")]
    #[allow(deprecated)]
    pub fn decrypt_list_iterable(
        &self,
        source: RawJsAsyncCipherSource,
        chunk_size: u32,
    ) -> BwStream<Result<CipherListView, Box<Cipher>>> {
        let key_store = self.key_store.clone();
        let client = self.client.clone();
        let chunk_size = chunk_size.max(1);
        let start = async move { Some((source, Decryptor::new(key_store, &client).await)) };
        BwStream::from_results(stream::once(start).flat_map(move |state| {
            stream::unfold(state, move |state| pull_decrypted(state, chunk_size))
        }))
    }

    /// Returns a [`CipherDecryptStream`] over `source`, a benchmark baseline for
    /// [`Self::decrypt_list_iterable`]. `next_chunk` on it pulls up to `chunk_size` ciphers (at
    /// least one).
    ///
    /// Strict decryption is decided by the feature flags when the stream is created.
    pub async fn decrypt_list_stream(
        &self,
        source: RawJsCipherSource,
        chunk_size: u32,
    ) -> CipherDecryptStream {
        CipherDecryptStream {
            source,
            chunk_size: chunk_size.max(1),
            decryptor: self.decryptor().await,
            failures: 0,
        }
    }

    /// [`Self::decrypt_list_stream`] for an `AsyncCipherSource`, returning a
    /// [`CipherAsyncDecryptStream`].
    pub async fn decrypt_list_async_stream(
        &self,
        source: RawJsAsyncCipherSource,
        chunk_size: u32,
    ) -> CipherAsyncDecryptStream {
        CipherAsyncDecryptStream {
            source,
            chunk_size: chunk_size.max(1),
            decryptor: self.decryptor().await,
            failures: 0,
        }
    }
}

impl CiphersClient {
    #[allow(deprecated)]
    async fn decryptor(&self) -> Decryptor {
        Decryptor::new(self.key_store.clone(), &self.client).await
    }
}

/// One step of [`CiphersClient::decrypt_list_iterable`]: pulls and decrypts the next chunk. The
/// state is `None` once the stream ended.
async fn pull_decrypted(
    state: Option<(RawJsAsyncCipherSource, Decryptor)>,
    chunk_size: u32,
) -> Option<(
    Result<Vec<Result<CipherListView, Box<Cipher>>>, JsValue>,
    Option<(RawJsAsyncCipherSource, Decryptor)>,
)> {
    let (source, decryptor) = state?;
    let chunk = match next_ciphers(&source, chunk_size).await {
        Ok(Some(chunk)) => chunk,
        Ok(None) => return None,
        Err(error) => return Some((Err(error), None)),
    };
    match decryptor.decrypt(chunk) {
        Ok(results) => Some((Ok(results), Some((source, decryptor)))),
        Err(error) => Some((Err(error.into()), None)),
    }
}

/// Awaits the next chunk of up to `max` ciphers from `source`, or `None` once it is exhausted.
async fn next_ciphers(
    source: &RawJsAsyncCipherSource,
    max: u32,
) -> Result<Option<Vec<Cipher>>, JsValue> {
    // `Promise.resolve` also accepts a source that returns its chunk without a Promise.
    let chunk = JsFuture::from(Promise::resolve(&source.next_chunk(max)?)).await?;
    if chunk.is_undefined() || chunk.is_null() {
        return Ok(None);
    }
    let chunk = Array::from(&chunk);
    // Converted per element into a vector of the exact length, as wasm_bindgen converts a
    // `Cipher[]` argument, so the chunk is not reallocated while it grows.
    let mut ciphers = Vec::with_capacity(chunk.length() as usize);
    for cipher in chunk.iter() {
        ciphers.push(Cipher::from_js(cipher)?);
    }
    Ok(Some(ciphers))
}

/// Decrypts ciphers to [`CipherListView`]s, pulling them from a `CipherSource` as they are
/// requested. A benchmark baseline for [`CiphersClient::decrypt_list_iterable`], which is the API
/// to use.
///
/// Ciphers that fail to decrypt are skipped and counted in [`Self::failure_count`]. A call returns
/// nothing only once the source is exhausted, never because every cipher it pulled failed.
///
/// The source is a JavaScript object and stays on the JavaScript thread, so the stream is used
/// directly from JavaScript and never crosses threads.
#[bitwarden_ffi::wasm_object]
pub struct CipherDecryptStream {
    source: RawJsCipherSource,
    chunk_size: u32,
    decryptor: Decryptor,
    failures: u32,
}

#[bitwarden_ffi::wasm_export]
impl CipherDecryptStream {
    /// Decrypts the next cipher, or returns `None` once the source is exhausted.
    pub fn next_item(&mut self) -> Result<Option<CipherListView>, JsValue> {
        Ok(self.pull(1)?.pop())
    }

    /// Decrypts the next `chunk_size` ciphers, fewer if some fail to decrypt or the source runs
    /// out. Returns an empty list once the source is exhausted.
    pub fn next_chunk(&mut self) -> Result<Vec<CipherListView>, JsValue> {
        self.pull(self.chunk_size)
    }

    /// The number of ciphers that failed to decrypt so far.
    pub fn failure_count(&self) -> u32 {
        self.failures
    }
}

impl CipherDecryptStream {
    /// Pulls up to `max` ciphers from the source and decrypts them, pulling again while a pull
    /// yields nothing, so an empty result means the source is exhausted.
    fn pull(&mut self, max: u32) -> Result<Vec<CipherListView>, JsValue> {
        loop {
            let Some(ciphers) = self.source.next_chunk(max)? else {
                return Ok(Vec::new());
            };
            let decrypted = keep_successes(self.decryptor.decrypt(ciphers)?, &mut self.failures);
            if !decrypted.is_empty() {
                return Ok(decrypted);
            }
        }
    }
}

/// [`CipherDecryptStream`] for an `AsyncCipherSource`. Every call awaits the source. A
/// benchmark baseline for [`CiphersClient::decrypt_list_iterable`], which is the API to use.
#[bitwarden_ffi::wasm_object]
pub struct CipherAsyncDecryptStream {
    source: RawJsAsyncCipherSource,
    chunk_size: u32,
    decryptor: Decryptor,
    failures: u32,
}

#[bitwarden_ffi::wasm_export]
impl CipherAsyncDecryptStream {
    /// Decrypts the next cipher, or resolves to `None` once the source is exhausted.
    pub async fn next_item_async(&mut self) -> Result<Option<CipherListView>, JsValue> {
        Ok(self.pull(1).await?.pop())
    }

    /// Decrypts the next `chunk_size` ciphers, fewer if some fail to decrypt or the source runs
    /// out. Resolves to an empty list once the source is exhausted.
    pub async fn next_chunk_async(&mut self) -> Result<Vec<CipherListView>, JsValue> {
        self.pull(self.chunk_size).await
    }

    /// The number of ciphers that failed to decrypt so far.
    pub fn failure_count(&self) -> u32 {
        self.failures
    }
}

impl CipherAsyncDecryptStream {
    /// [`CipherDecryptStream::pull`], awaiting the source.
    async fn pull(&mut self, max: u32) -> Result<Vec<CipherListView>, JsValue> {
        loop {
            let Some(ciphers) = next_ciphers(&self.source, max).await? else {
                return Ok(Vec::new());
            };
            let decrypted = keep_successes(self.decryptor.decrypt(ciphers)?, &mut self.failures);
            if !decrypted.is_empty() {
                return Ok(decrypted);
            }
        }
    }
}

/// The decrypted views of `results`, adding the failures to `failures`.
fn keep_successes(
    results: Vec<Result<CipherListView, Box<Cipher>>>,
    failures: &mut u32,
) -> Vec<CipherListView> {
    let mut views = Vec::with_capacity(results.len());
    for result in results {
        match result {
            Ok(view) => views.push(view),
            Err(_) => *failures += 1,
        }
    }
    views
}

/// Decrypts chunks of ciphers with the same key store path as
/// [`CiphersClient::decrypt_list_with_failures`], keeping each result in its cipher's position.
struct Decryptor {
    key_store: KeyStore<KeySlotIds>,
    strict: bool,
}

impl Decryptor {
    /// Reads whether to decrypt strictly from `client`'s feature flags.
    async fn new(key_store: KeyStore<KeySlotIds>, client: &Client) -> Self {
        Self {
            key_store,
            strict: client.flags().get().await.strict_cipher_decryption,
        }
    }

    /// Decrypts `ciphers` in order, returning each cipher that fails in its place.
    ///
    /// A missing user key fails the whole chunk with [`DecryptStreamError::VaultLocked`]: no
    /// cipher can decrypt then, and a locked vault is not a problem with any one cipher. Any other
    /// failure, such as a cipher key that cannot be unwrapped, is that cipher's.
    fn decrypt(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<Vec<Result<CipherListView, Box<Cipher>>>, DecryptStreamError> {
        if self.strict {
            let wrapped: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            self.decrypt_each(&wrapped, |strict| &strict.0)
        } else {
            self.decrypt_each(&ciphers, |cipher| cipher)
        }
    }

    /// Decrypts `items` by reference and clones only the ciphers that fail: moving each
    /// [`Cipher`], over 5 KB, out of the chunk measured about 70% more linear memory per chunk.
    fn decrypt_each<D>(
        &self,
        items: &[D],
        cipher: impl Fn(&D) -> &Cipher,
    ) -> Result<Vec<Result<CipherListView, Box<Cipher>>>, DecryptStreamError>
    where
        D: Decryptable<KeySlotIds, SymmetricKeySlotId, CipherListView>
            + IdentifyKey<SymmetricKeySlotId>,
    {
        let mut ctx = self.key_store.context();
        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            return Err(DecryptStreamError::VaultLocked);
        }

        Ok(items
            .iter()
            .map(|item| {
                let result = item.decrypt(&mut ctx, item.key_identifier());
                ctx.clear_local();
                result.map_err(|_| Box::new(cipher(item).clone()))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::{super::tests::test_cipher, *};
    use crate::VaultClientExt;

    async fn decryptor() -> (Client, Decryptor) {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let key_store = client.vault().ciphers().key_store.clone();
        (
            client,
            Decryptor {
                key_store,
                strict: false,
            },
        )
    }

    async fn strict_decryptor() -> (Client, Decryptor) {
        let (client, decryptor) = decryptor().await;
        (
            client,
            Decryptor {
                strict: true,
                ..decryptor
            },
        )
    }

    /// A cipher whose key is wrapped with an organization key the store does not hold, so the
    /// cipher key cannot be unwrapped. A missing key for a single field only blanks that field.
    fn cipher_of_unknown_organization() -> Cipher {
        Cipher {
            id: Some("9b1e1d8c-0000-4000-8000-000000000002".parse().unwrap()),
            organization_id: Some("9b1e1d8c-0000-4000-8000-000000000001".parse().unwrap()),
            key: Some("2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=".parse().unwrap()),
            ..test_cipher()
        }
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place() {
        let (_client, decryptor) = decryptor().await;
        let bad = cipher_of_unknown_organization();

        let results = decryptor
            .decrypt(vec![test_cipher(), bad.clone(), test_cipher()])
            .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap().name, "234234");
        assert_eq!(results[1].as_ref().unwrap_err().id, bad.id);
        assert_eq!(results[2].as_ref().unwrap().name, "234234");
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place_when_strict() {
        let (_client, decryptor) = strict_decryptor().await;
        let bad = cipher_of_unknown_organization();

        let results = decryptor.decrypt(vec![bad.clone(), test_cipher()]).unwrap();

        assert_eq!(results[0].as_ref().unwrap_err().id, bad.id);
        assert_eq!(results[1].as_ref().unwrap().name, "234234");
    }

    #[tokio::test]
    async fn fails_the_whole_chunk_when_the_vault_is_locked() {
        let (_client, decryptor) = decryptor().await;
        decryptor.key_store.clear();

        let result = decryptor.decrypt(vec![test_cipher()]);

        assert!(matches!(result, Err(DecryptStreamError::VaultLocked)));
    }

    #[tokio::test]
    async fn decrypts_an_empty_chunk_to_nothing() {
        let (_client, decryptor) = decryptor().await;

        assert!(decryptor.decrypt(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn keep_successes_counts_the_failures() {
        let mut failures = 1;
        let views = keep_successes(
            vec![Err(Box::new(test_cipher())), Err(Box::new(test_cipher()))],
            &mut failures,
        );

        assert!(views.is_empty());
        assert_eq!(failures, 3);
    }
}
