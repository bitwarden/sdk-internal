//! JS-side reader/writer contracts and chunk helper for streaming attachment I/O.

#![cfg(feature = "wasm")]

use bitwarden_crypto::{ChunkReader, ChunkWriter, CryptoError};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_ATTACHMENT_BYTE_STREAMS: &'static str = r#"
/**
 * Async chunked-reader contract expected by the SDK's streaming attachment APIs.
 * Shape matches `ReadableStreamDefaultReader.read()` — each call resolves to
 * `{ value, done }`. When `done === true`, `value` is ignored. Hosts can implement
 * this by passing through a `fetch().body.getReader()`.
 */
export interface AttachmentByteReader {
    read(): Promise<{ value: Uint8Array; done: boolean }>;
}

/**
 * Async chunked-writer contract expected by the SDK's streaming attachment APIs.
 *
 * **Tentative-write contract:** bytes passed to `write()` are produced by the SDK *before*
 * the input stream has been fully authenticated. Hosts MUST NOT act on those bytes
 * (upload them, persist them where they can't be rolled back, display them) until the
 * enclosing SDK call resolves `Ok`. If the SDK call rejects, the bytes already passed to
 * `write()` are unauthenticated and must be thrown away.
 */
export interface AttachmentByteWriter {
    write(chunk: Uint8Array): Promise<void>;
    /** Signals end-of-stream after a successful run. Implies all prior writes are now authenticated. */
    close(): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "AttachmentByteReader")]
    pub type AttachmentByteReader;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn read(this: &AttachmentByteReader) -> Result<JsValue, JsValue>;

    /// Bytes passed to [`Self::write`] are unauthenticated until the enclosing SDK call
    /// resolves `Ok` and [`Self::close`] has been invoked; on `Err`, hosts must drop them.
    #[wasm_bindgen(typescript_type = "AttachmentByteWriter")]
    pub type AttachmentByteWriter;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn write(
        this: &AttachmentByteWriter,
        chunk: js_sys::Uint8Array,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn close(this: &AttachmentByteWriter) -> Result<(), JsValue>;
}

/// Reads one chunk from [`AttachmentByteReader`]; `Ok(None)` signals end of stream.
///
/// Uses `js_sys::Reflect` + `Uint8Array` directly instead of `serde_wasm_bindgen` because
/// the serde deserializer can't read a `Uint8Array` into a `Vec<u8>` field — it expects
/// `serde_bytes`-compatible bytes, not a JS typed array.
pub(crate) async fn read_chunk(
    reader: &AttachmentByteReader,
) -> Result<Option<Vec<u8>>, CryptoError> {
    let result = reader.read().await.map_err(|_| CryptoError::StreamIo)?;
    // Missing/non-boolean `done` is a host protocol violation — reject rather than
    // silently spinning the read loop.
    let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
        .map_err(|_| CryptoError::StreamIo)?
        .as_bool()
        .ok_or(CryptoError::StreamIo)?;
    if done {
        return Ok(None);
    }
    let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
        .map_err(|_| CryptoError::StreamIo)?;
    if value.is_undefined() || value.is_null() {
        return Ok(Some(Vec::new()));
    }
    Ok(Some(js_sys::Uint8Array::new(&value).to_vec()))
}

/// Wraps the JS [`AttachmentByteReader`], optionally prepending payload bytes that arrived
/// alongside the legacy attachment header (so they're handed to the streaming decryptor
/// before the next `read()` call).
pub(crate) struct PayloadReader {
    initial: Option<Vec<u8>>,
    reader: AttachmentByteReader,
}

impl PayloadReader {
    pub(crate) fn new(reader: AttachmentByteReader, initial: Vec<u8>) -> Self {
        let initial = (!initial.is_empty()).then_some(initial);
        Self { initial, reader }
    }
}

impl ChunkReader for PayloadReader {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CryptoError> {
        if let Some(bytes) = self.initial.take() {
            return Ok(Some(bytes));
        }
        read_chunk(&self.reader).await
    }
}

/// Adapter wrapping [`AttachmentByteWriter`] for the [`ChunkWriter`] trait.
pub(crate) struct AttachmentWriterAdapter(AttachmentByteWriter);

impl AttachmentWriterAdapter {
    pub(crate) fn new(writer: AttachmentByteWriter) -> Self {
        Self(writer)
    }
}

impl ChunkWriter for AttachmentWriterAdapter {
    async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let view = js_sys::Uint8Array::from(bytes);
        self.0.write(view).await.map_err(|_| CryptoError::StreamIo)
    }

    async fn close(&mut self) -> Result<(), CryptoError> {
        self.0.close().await.map_err(|_| CryptoError::StreamIo)
    }
}
