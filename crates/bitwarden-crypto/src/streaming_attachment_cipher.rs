//! Streaming AES-256-CBC + HMAC primitives for the attachment-upgrade pipeline.
//!
//! [`StreamingAttachmentDecryptor::next_chunk`] emits plaintext bytes *before* the HMAC
//! is verified by [`StreamingAttachmentDecryptor::finalize`]. Callers MUST NOT act on
//! those bytes (upload, persist, display) until `finalize` returns `Ok`.
//!
//! The [`ChunkReader`] / [`ChunkWriter`] traits intentionally don't require `Send` on the
//! returned futures so they can be implemented by `!Send` host bindings (e.g. WASM types
//! holding `JsValue`).
#![allow(async_fn_in_trait)]

use crate::{
    CryptoError, KeyStoreContext,
    aes::{StreamingAes256CbcHmacDecryptor, StreamingAes256CbcHmacEncryptor},
    traits::KeySlotIds,
};

/// Host-supplied source of ciphertext chunks consumed by [`StreamingAttachmentDecryptor`].
pub trait ChunkReader {
    /// Returns the next chunk, or `Ok(None)` when the stream is exhausted.
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CryptoError>;
}

/// Host-supplied sink of ciphertext chunks produced by [`StreamingAttachmentEncryptor`].
pub trait ChunkWriter {
    /// Pushes the next ciphertext chunk to the sink.
    async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;
    /// Signals end-of-stream after a successful encrypt run; called by
    /// [`StreamingAttachmentEncryptor::finalize`] only on the `Ok` path.
    async fn close(&mut self) -> Result<(), CryptoError>;
}

/// IV + MAC + total ciphertext bytes produced by [`StreamingAttachmentEncryptor::finalize`].
pub struct StreamingAttachmentFinal {
    /// 16-byte AES-CBC IV.
    pub iv: [u8; 16],
    /// 32-byte HMAC-SHA256 tag over IV + ciphertext.
    pub mac: [u8; 32],
    /// Total bytes pushed through the writer (ciphertext only, excluding the IV/MAC
    /// header the caller will prepend before uploading).
    pub size: usize,
}

/// Streaming AES-256-CBC + HMAC-SHA256 decryptor that pulls ciphertext from a
/// [`ChunkReader`] and yields plaintext via [`Self::next_chunk`].
pub struct StreamingAttachmentDecryptor<R> {
    reader: R,
    inner: StreamingAes256CbcHmacDecryptor,
}

impl<R: ChunkReader> StreamingAttachmentDecryptor<R> {
    /// Resolves the [`crate::Aes256CbcHmacKey`] at `key_id` from `ctx` and primes the
    /// decryptor with `iv`. Returns [`CryptoError::InvalidKey`] when the slot holds a key
    /// of a different type.
    pub fn new<Ids: KeySlotIds>(
        reader: R,
        key_id: Ids::Symmetric,
        ctx: &KeyStoreContext<'_, Ids>,
        iv: &[u8; 16],
    ) -> Result<Self, CryptoError> {
        let key = ctx.get_aes256_cbc_hmac_key(key_id)?;
        Ok(Self {
            reader,
            inner: StreamingAes256CbcHmacDecryptor::new(iv, key),
        })
    }

    /// Pulls ciphertext chunks from the reader until at least one decrypted block is
    /// available; returns `Ok(None)` when the reader is exhausted.
    ///
    /// **WARNING:** returned bytes are unauthenticated until [`Self::finalize`] returns
    /// `Ok`. Callers MUST fully drain the decrypted stream and discard the entire result
    /// if [`Self::finalize`] does not return `Ok` — do not upload, persist, or display
    /// the bytes until authentication succeeds.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CryptoError> {
        loop {
            match self.reader.next_chunk().await? {
                None => return Ok(None),
                Some(bytes) if bytes.is_empty() => continue,
                Some(bytes) => {
                    let plaintext = self.inner.update(&bytes);
                    if !plaintext.is_empty() {
                        return Ok(Some(plaintext));
                    }
                }
            }
        }
    }

    /// Verifies the HMAC against `expected_mac` and returns the final PKCS7-unpadded
    /// plaintext block(s). Must be called even after [`Self::next_chunk`] returns
    /// `Ok(None)` — otherwise the bytes already emitted are unauthenticated.
    pub fn finalize(self, expected_mac: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        self.inner.finalize(expected_mac)
    }
}

/// Streaming AES-256-CBC + HMAC-SHA256 encryptor that pushes ciphertext to a
/// [`ChunkWriter`].
pub struct StreamingAttachmentEncryptor<W> {
    writer: W,
    inner: StreamingAes256CbcHmacEncryptor,
    size: usize,
}

impl<W: ChunkWriter> StreamingAttachmentEncryptor<W> {
    /// Resolves the [`crate::Aes256CbcHmacKey`] at `key_id` from `ctx` and generates a
    /// random IV. Returns [`CryptoError::InvalidKey`] when the slot holds a key of a
    /// different type.
    pub fn new<Ids: KeySlotIds>(
        writer: W,
        key_id: Ids::Symmetric,
        ctx: &KeyStoreContext<'_, Ids>,
    ) -> Result<Self, CryptoError> {
        let key = ctx.get_aes256_cbc_hmac_key(key_id)?;
        Ok(Self {
            writer,
            inner: StreamingAes256CbcHmacEncryptor::new(key),
            size: 0,
        })
    }

    /// Encrypts `plaintext` and pushes any ciphertext blocks ready to emit to the writer.
    pub async fn write_plaintext(&mut self, plaintext: &[u8]) -> Result<(), CryptoError> {
        let ciphertext = self.inner.update(plaintext);
        if !ciphertext.is_empty() {
            self.writer.write_chunk(&ciphertext).await?;
            self.size += ciphertext.len();
        }
        Ok(())
    }

    /// Encrypts the final PKCS7-padded block(s), pushes the trailing ciphertext to the
    /// writer, calls [`ChunkWriter::close`], and returns the IV + MAC + total size.
    pub async fn finalize(mut self) -> Result<StreamingAttachmentFinal, CryptoError> {
        let final_ = self.inner.finalize();
        if !final_.trailing_ciphertext.is_empty() {
            self.writer.write_chunk(&final_.trailing_ciphertext).await?;
            self.size += final_.trailing_ciphertext.len();
        }
        self.writer.close().await?;
        Ok(StreamingAttachmentFinal {
            iv: final_.iv,
            mac: final_.mac,
            size: self.size,
        })
    }
}
