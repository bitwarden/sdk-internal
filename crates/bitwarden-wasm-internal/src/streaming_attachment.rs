use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{
    KeyStore, StreamingAttachmentDecryptor, StreamingAttachmentEncryptor, SymmetricCryptoKey,
};
use futures::TryStreamExt;
use tokio::io::AsyncWriteExt;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use wasm_bindgen::prelude::*;

/// Decrypts a streaming-attachment-encrypted wire stream.
///
/// Takes a `ReadableStream` of encrypted bytes and returns a `ReadableStream` of decrypted
/// plaintext bytes. The plaintext is produced lazily as the encrypted stream is consumed —
/// the full blob is never materialized in memory. Authentication is only validated once the
/// full encrypted stream has been consumed; consumers must not act on the plaintext bytes
/// before the returned stream reaches its end.
#[wasm_bindgen]
pub fn decrypt_attachment_stream(
    key: SymmetricCryptoKey,
    encrypted: web_sys::ReadableStream,
) -> Result<web_sys::ReadableStream, JsValue> {
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context();
    let key_slot = ctx.add_local_symmetric_key(key);

    let input = wasm_streams::ReadableStream::from_raw(encrypted)
        .into_async_read()
        .compat();
    let decryptor = StreamingAttachmentDecryptor::new(key_slot, ctx, input)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    drop(store);

    let plaintext = tokio_util::io::ReaderStream::new(decryptor)
        .map_ok(|chunk| {
            let arr = js_sys::Uint8Array::new_with_length(chunk.len() as u32);
            arr.copy_from(&chunk);
            JsValue::from(arr)
        })
        .map_err(|e| JsValue::from_str(&e.to_string()));

    Ok(wasm_streams::ReadableStream::from_stream(plaintext).into_raw())
}

/// Encrypts a plaintext stream using the streaming attachment cipher.
///
/// Takes a `ReadableStream` of plaintext bytes and returns a `ReadableStream` of encrypted
/// wire bytes. Encryption runs lazily on the JS event loop; if the JS consumer cancels the
/// returned stream the underlying pipe shuts down and the task exits.
#[wasm_bindgen]
pub fn encrypt_attachment_stream(
    key: SymmetricCryptoKey,
    plaintext: web_sys::ReadableStream,
) -> Result<web_sys::ReadableStream, JsValue> {
    let mut input = wasm_streams::ReadableStream::from_raw(plaintext)
        .into_async_read()
        .compat();

    let (writer_half, reader_half) = tokio::io::duplex(64 * 1024);
    let mut encryptor = StreamingAttachmentEncryptor::new(key, writer_half)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    wasm_bindgen_futures::spawn_local(async move {
        if tokio::io::copy(&mut input, &mut encryptor).await.is_ok() {
            let _ = encryptor.shutdown().await;
        }
    });

    let stream = tokio_util::io::ReaderStream::new(reader_half)
        .map_ok(|chunk| {
            let arr = js_sys::Uint8Array::new_with_length(chunk.len() as u32);
            arr.copy_from(&chunk);
            JsValue::from(arr)
        })
        .map_err(|e| JsValue::from_str(&e.to_string()));

    Ok(wasm_streams::ReadableStream::from_stream(stream).into_raw())
}
