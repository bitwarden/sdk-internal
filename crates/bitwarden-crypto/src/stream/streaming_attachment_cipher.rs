//! `AsyncRead` / `AsyncWrite` wrapper around the streaming attachment ciphers.
//!
//! ## Wire format
//!
//! ```text
//! [discriminator (1 byte)] [format-specific header] [ciphertext...]
//! ```
//!
//! - `0x02` is AES256-CBC-HMAC-Legacy-Stream
//!
//! `0x02` matches the long-standing `EncString::Aes256Cbc_HmacSha256_B64 = 2` numbering. The
//! chunked-AEAD discriminators are new to the streaming wire format and do not correspond to
//! any `EncString` variant.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    CryptoError, SymmetricCryptoKey,
    stream::{
        ChunkDecryptionResult, ChunkEncryptionResult, StreamingDecryptor, StreamingEncryptor,
        aes256_cbc_hmac_legacy_stream::{
            StreamingAes256CbcHmacDecryptor, StreamingAes256CbcHmacEncryptor,
        },
    },
};

enum AttachmentFormatDiscriminator {
    Aes256CbcHmacLegacyStream = 0x02,
}

impl From<u8> for AttachmentFormatDiscriminator {
    fn from(value: u8) -> Self {
        match value {
            0x02 => Self::Aes256CbcHmacLegacyStream,
            _ => panic!("unknown discriminator byte"),
        }
    }
}

impl From<AttachmentFormatDiscriminator> for u8 {
    fn from(discriminator: AttachmentFormatDiscriminator) -> Self {
        discriminator as u8
    }
}

const READ_SCRATCH_SIZE: usize = 8 * 1024;

// An enum representing the state of the streaming attachment decryptor. This is a state machine
// for attachment stream parsing. As soon as the header bytes are parsed that discriminate the encryption
// type, the state transitions to the appropriate streaming decryptor.
enum StreamDecryptorState {
    /// First byte of the wire has not yet been observed.
    NeedDiscriminator { key: SymmetricCryptoKey },
    Aes256CbcHmacLegacyStream {
        decryptor: Box<StreamingAes256CbcHmacDecryptor>,
    },
    /// Discard the stream — decryption failed.
    Error,
}

/// AsyncRead adapter that decrypts a streaming-attachment-encrypted wire stream from `R`
/// and exposes the decrypted plaintext via [`AsyncRead`]. The cipher is selected by the
/// 1-byte discriminator at the start of the wire and must agree with the supplied key.
pub struct StreamingAttachmentDecryptor<R> {
    inner: R,
    state: StreamDecryptorState,
    /// Decrypted plaintext awaiting copy into the caller's buffer.
    plaintext_buf: Vec<u8>,
    plaintext_head: usize,
    /// Set once the inner reader has returned EOF; triggers the underlying `update(_, true)`.
    inner_eof: bool,
}

impl<R> StreamingAttachmentDecryptor<R> {
    /// Construct a decryptor. The key variant determines which cipher's wire format is
    /// expected; the discriminator on the wire is validated against it on the first byte.
    pub fn new(key: SymmetricCryptoKey, inner: R) -> Result<Self, CryptoError> {
        match &key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => Ok(Self {
                inner,
                state: StreamDecryptorState::NeedDiscriminator { key },
                plaintext_buf: Vec::new(),
                plaintext_head: 0,
                inner_eof: false,
            }),
            _ => Err(CryptoError::OperationNotSupported(
                crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
            )),
        }
    }

    fn drain_plaintext_into(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.plaintext_head >= self.plaintext_buf.len() {
            return false;
        }
        let available = &self.plaintext_buf[self.plaintext_head..];
        let n = available.len().min(buf.remaining());
        if n == 0 {
            return false;
        }
        buf.put_slice(&available[..n]);
        self.plaintext_head += n;
        if self.plaintext_head == self.plaintext_buf.len() {
            self.plaintext_buf.clear();
            self.plaintext_head = 0;
        }
        true
    }

    fn feed_wire_bytes(&mut self, mut data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Consume the discriminator byte if the state machine hasn't done so yet.
        if matches!(self.state, StreamDecryptorState::NeedDiscriminator { .. }) {
            let disc = AttachmentFormatDiscriminator::from(data[0]);
            data = &data[1..];

            let key = match std::mem::replace(&mut self.state, StreamDecryptorState::Error) {
                StreamDecryptorState::NeedDiscriminator { key } => key,
                _ => unreachable!("just matched on NeedDiscriminator"),
            };

            match disc {
                AttachmentFormatDiscriminator::Aes256CbcHmacLegacyStream => {
                    let dec = StreamingAes256CbcHmacDecryptor::try_new(&key).map_err(|_| {
                        io::Error::other(
                            "streaming attachment: key does not match discriminator 0x02",
                        )
                    })?;
                    self.state = StreamDecryptorState::Aes256CbcHmacLegacyStream { decryptor: Box::new(dec) };
                }
                _ => {
                    return Err(io::Error::other(
                        "streaming attachment: unknown discriminator byte",
                    ));
                }
            }
        }

        if data.is_empty() {
            return Ok(());
        }

        match &mut self.state {
            StreamDecryptorState::Aes256CbcHmacLegacyStream { decryptor: dec } => match dec.update(data, false) {
                ChunkDecryptionResult::NeedMoreData => Ok(()),
                ChunkDecryptionResult::DecryptedChunk(bytes) => {
                    self.plaintext_buf.extend_from_slice(&bytes);
                    Ok(())
                }
                ChunkDecryptionResult::FinalDecryptedChunk(_) | ChunkDecryptionResult::Error => {
                    self.state = StreamDecryptorState::Error;
                    Err(io::Error::other(
                        "streaming attachment: AES-CBC-HMAC decryption error",
                    ))
                }
            },
            StreamDecryptorState::Error => Ok(()),
            StreamDecryptorState::NeedDiscriminator { .. } => unreachable!("handled above"),
        }
    }

    fn finalize_underlying(&mut self) -> io::Result<()> {
        match std::mem::replace(&mut self.state, StreamDecryptorState::Error) {
            StreamDecryptorState::NeedDiscriminator { .. } => Err(io::Error::other(
                "streaming attachment: truncated before discriminator",
            )),
            StreamDecryptorState::Aes256CbcHmacLegacyStream { decryptor: mut dec } => match dec.update(&[], true) {
                ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                    self.plaintext_buf.extend_from_slice(&bytes);
                    self.state = StreamDecryptorState::Done;
                    Ok(())
                }
                _ => Err(io::Error::other(
                    "streaming attachment: AES-CBC-HMAC finalize failed (truncated or tampered)",
                )),
            },
            StreamDecryptorState::Error => Err(io::Error::other("streaming attachment: decryption error")),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for StreamingAttachmentDecryptor<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Drain decrypted plaintext into the caller's buffer first.
            if this.drain_plaintext_into(buf) {
                return Poll::Ready(Ok(()));
            }

            // 2. If we already errored, surface it.
            if matches!(this.state, StreamDecryptorState::Error) {
                return Poll::Ready(Err(io::Error::other(
                    "streaming attachment: decryption error",
                )));
            }

            // 3. If we're done draining and the underlying stream is finalized, signal EOF.
            if matches!(this.state, StreamDecryptorState::Done) {
                return Poll::Ready(Ok(()));
            }

            // 4. If the inner reader has hit EOF, run the terminal finalize and loop to drain.
            if this.inner_eof {
                if let Err(e) = this.finalize_underlying() {
                    return Poll::Ready(Err(e));
                }
                continue;
            }

            // 5. Otherwise, pull more bytes from the inner reader.
            let mut scratch = [0u8; READ_SCRATCH_SIZE];
            let mut scratch_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut scratch_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.state = StreamDecryptorState::Error;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    let filled = scratch_buf.filled();
                    if filled.is_empty() {
                        this.inner_eof = true;
                    } else if let Err(e) = this.feed_wire_bytes(filled) {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
    }
}

enum StreamEncryptorState {
    Aes256CbcHmacLegacyStream {
        encryptor: Box<StreamingAes256CbcHmacEncryptor>,
    },
    /// `update(_, true)` has been called; the wire payload is queued in `pending_write`
    /// and being drained to the inner writer.
    Finalized,
    /// All bytes flushed to the inner writer and `inner.poll_shutdown` completed.
    Done,
    Error,
}

/// AsyncWrite adapter that takes plaintext and writes a streaming-attachment-encrypted
/// wire stream to `W`. The cipher is selected by the [`SymmetricCryptoKey`] variant (plus, for
/// the chunked-AEAD path, an explicit [`AeadAlgorithm`]). The 1-byte discriminator is emitted
/// before any plaintext is encrypted; the final `header || ciphertext` payload is emitted
/// during `poll_shutdown`.
pub struct StreamingAttachmentEncryptor<W> {
    inner: W,
    state: StreamEncryptorState,
    /// Bytes that need to be written to `inner` before this wrapper can make further progress.
    /// At construction this holds the 1-byte discriminator; during shutdown it holds the
    /// finalized wire payload.
    pending_write: Vec<u8>,
    pending_head: usize,
}

impl<W> StreamingAttachmentEncryptor<W> {
    /// Construct an encryptor.
    ///
    /// - When `key` is an [`SymmetricCryptoKey::Aes256CbcHmacKey`], `aead_algorithm` must be `None`
    ///   — the AES-CBC-HMAC legacy format is used.
    /// 
    /// The corresponding discriminator byte is queued as the first wire byte.
    pub fn new(
        key: SymmetricCryptoKey,
        inner: W,
    ) -> Result<Self, CryptoError> {
        let (state, discriminator) = match &key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => {
                let enc = StreamingAes256CbcHmacEncryptor::try_new(&key).map_err(|_| {
                    CryptoError::OperationNotSupported(
                        crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
                    )
                })?;
                (
                    StreamEncryptorState::Aes256CbcHmacLegacyStream { encryptor: Box::new(enc) },
                    AttachmentFormatDiscriminator::Aes256CbcHmacLegacyStream.into(),
                )
            }
            _ => {
                return Err(CryptoError::OperationNotSupported(
                    crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
                ));
            }
        };

        Ok(Self {
            inner,
            state,
            pending_write: vec![discriminator],
            pending_head: 0,
        })
    }
}

impl<W: AsyncWrite + Unpin> StreamingAttachmentEncryptor<W> {
    /// Drives `inner.poll_write` until `pending_write` is fully drained or the writer returns
    /// `Pending`. Returns `Ready(Ok(()))` once the pending buffer is empty.
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_head < self.pending_write.len() {
            let to_write = &self.pending_write[self.pending_head..];
            match Pin::new(&mut self.inner).poll_write(cx, to_write) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.state = StreamEncryptorState::Error;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(0)) => {
                    self.state = StreamEncryptorState::Error;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "streaming attachment: inner writer accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_head += n;
                }
            }
        }
        self.pending_write.clear();
        self.pending_head = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StreamingAttachmentEncryptor<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }
        if matches!(this.state, StreamEncryptorState::Finalized | StreamEncryptorState::Done) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: write after shutdown",
            )));
        }

        // Make sure the discriminator (and any other queued bytes) are committed first.
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let result = match &mut this.state {
            StreamEncryptorState::Aes256CbcHmacLegacyStream { encryptor: enc } => enc.update(buf, false),
            _ => unreachable!("state checked above"),
        };

        match result {
            ChunkEncryptionResult::Buffered => Poll::Ready(Ok(buf.len())),
            ChunkEncryptionResult::FinalEncrypted { .. } | ChunkEncryptionResult::Error => {
                this.state = StreamEncryptorState::Error;
                Poll::Ready(Err(io::Error::other(
                    "streaming attachment: encryption error",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain whatever is pending (discriminator at startup, or nothing during steady state),
        // then flush the inner writer.
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain any pending header/discriminator bytes.
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }

        // 2. If we haven't finalized yet, call update(_, true) and queue the wire payload.
        if matches!(
            this.state,
            StreamEncryptorState::Aes256CbcHmacLegacyStream { .. } | StreamEncryptorState::ChunkedAead { .. }
        ) {
            let old = std::mem::replace(&mut this.state, StreamEncryptorState::Error);
            let wire = match old {
                StreamEncryptorState::Aes256CbcHmacLegacyStream { encryptor: mut enc } => match enc.update(&[], true) {
                    ChunkEncryptionResult::FinalEncryptedChunk(ciphertext) => ciphertext,
                    _ => {
                        return Poll::Ready(Err(io::Error::other(
                            "streaming attachment: AES-CBC-HMAC finalize failed",
                        )));
                    }
                },
                _ => unreachable!("state checked above"),
            };

            this.pending_write = wire;
            this.pending_head = 0;
            this.state = StreamEncryptorState::Finalized;
        }

        // 3. Drain the finalized wire payload to the inner writer.
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }

        // 4. Shut down the inner writer.
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                this.state = StreamEncryptorState::Done;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.state = StreamEncryptorState::Error;
                Poll::Ready(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use hybrid_array::{Array, sizes::U32};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{Aes256CbcHmacKey, KeyId, XChaCha20Poly1305Key};

    /// In-memory `AsyncWrite` sink that records all writes into a shared buffer so a test can
    /// inspect the on-wire bytes after the encryptor is dropped.
    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl AsyncWrite for SharedSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0
                .lock()
                .expect("mutex poisoned")
                .extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn aes_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
            enc_key: Box::pin([0u8; 32].into()),
            mac_key: Box::pin([1u8; 32].into()),
        })
    }

    fn aead_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            key_id: KeyId::make(),
            enc_key: Pin::new(Box::new(Array::<u8, U32>::from([0u8; 32]))),
            supported_operations: vec![],
        })
    }

    /// Drive the encryptor to completion against an in-memory sink and return the produced wire.
    async fn encrypt_via_shared(
        key: SymmetricCryptoKey,
        algorithm: Option<AeadAlgorithm>,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = SharedSink(shared.clone());
        let mut enc = StreamingAttachmentEncryptor::new(key, algorithm, sink)
            .expect("encryptor construction");
        enc.write_all(plaintext).await.expect("write_all");
        enc.shutdown().await.expect("shutdown");
        shared.lock().expect("mutex poisoned").clone()
    }

    async fn decrypt_wire(key: SymmetricCryptoKey, wire: &[u8]) -> io::Result<Vec<u8>> {
        let mut dec = StreamingAttachmentDecryptor::new(key, wire).expect("decryptor construction");
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await?;
        Ok(out)
    }

    const PLAINTEXT_SHORT: &[u8] =
        b"streaming attachment cipher: AsyncRead/AsyncWrite roundtrip test plaintext.";

    #[tokio::test]
    async fn aes_cbc_hmac_roundtrip() {
        let wire = encrypt_via_shared(aes_key(), None, PLAINTEXT_SHORT).await;
        assert_eq!(
            wire.first().copied(),
            Some(AES256_CBC_HMAC_LEGACY_STREAM_DISCRIMINATOR),
            "wire should start with the AES-CBC-HMAC discriminator"
        );
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }

    #[tokio::test]
    async fn chunked_aead_aes_gcm_roundtrip() {
        let wire =
            encrypt_via_shared(aead_key(), Some(AeadAlgorithm::Aes256Gcm), PLAINTEXT_SHORT).await;
        assert_eq!(
            wire.first().copied(),
            Some(CHUNKED_AEAD_AES_256_GCM_DISCRIMINATOR),
            "wire should start with the chunked-AEAD AES-256-GCM discriminator"
        );
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }

    #[tokio::test]
    async fn chunked_aead_chacha20_poly1305_roundtrip() {
        let wire = encrypt_via_shared(
            aead_key(),
            Some(AeadAlgorithm::ChaCha20Poly1305),
            PLAINTEXT_SHORT,
        )
        .await;
        assert_eq!(
            wire.first().copied(),
            Some(CHUNKED_AEAD_CHACHA20_POLY1305_DISCRIMINATOR),
            "wire should start with the chunked-AEAD ChaCha20-Poly1305 discriminator"
        );
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }

    #[tokio::test]
    async fn aes_cbc_hmac_roundtrip_multi_kb() {
        // Bigger plaintext crossing many CBC blocks.
        let plaintext: Vec<u8> = (0..(32 * 1024 + 137)).map(|i| (i % 251) as u8).collect();
        let wire = encrypt_via_shared(aes_key(), None, &plaintext).await;
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, plaintext);
    }

    #[tokio::test]
    async fn chunked_aead_aes_gcm_roundtrip_multi_chunk() {
        // > PLAINTEXT_CHUNK_SIZE (64 KiB) so we cross STREAM chunk boundaries.
        let plaintext: Vec<u8> = (0..(64 * 1024 * 2 + 503))
            .map(|i| (i % 251) as u8)
            .collect();
        let wire = encrypt_via_shared(aead_key(), Some(AeadAlgorithm::Aes256Gcm), &plaintext).await;
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, plaintext);
    }

    #[tokio::test]
    async fn chunked_aead_chacha20_poly1305_roundtrip_multi_chunk() {
        let plaintext: Vec<u8> = (0..(64 * 1024 * 2 + 503))
            .map(|i| (i % 251) as u8)
            .collect();
        let wire = encrypt_via_shared(
            aead_key(),
            Some(AeadAlgorithm::ChaCha20Poly1305),
            &plaintext,
        )
        .await;
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, plaintext);
    }

    #[tokio::test]
    async fn unknown_discriminator_byte_fails() {
        // Build a wire starting with 0xFF (not a known discriminator).
        let mut wire = vec![0xFFu8];
        wire.extend_from_slice(&[0u8; 32]);
        let err = decrypt_wire(aes_key(), &wire)
            .await
            .expect_err("expected error for unknown discriminator");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn discriminator_key_mismatch_fails() {
        // Encrypt with AES-CBC-HMAC, attempt to decrypt with the AEAD key.
        let wire = encrypt_via_shared(aes_key(), None, PLAINTEXT_SHORT).await;
        let err = decrypt_wire(aead_key(), &wire)
            .await
            .expect_err("expected error for key/discriminator mismatch");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn truncated_wire_fails_aes() {
        let wire = encrypt_via_shared(aes_key(), None, PLAINTEXT_SHORT).await;
        let truncated = &wire[..wire.len() - 10];
        let err = decrypt_wire(aes_key(), truncated)
            .await
            .expect_err("expected error for truncated wire");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn truncated_wire_fails_chunked_aead_aes_gcm() {
        let wire =
            encrypt_via_shared(aead_key(), Some(AeadAlgorithm::Aes256Gcm), PLAINTEXT_SHORT).await;
        let truncated = &wire[..wire.len() - 5];
        let err = decrypt_wire(aead_key(), truncated)
            .await
            .expect_err("expected error for truncated wire");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn truncated_wire_fails_chunked_aead_chacha20_poly1305() {
        let wire = encrypt_via_shared(
            aead_key(),
            Some(AeadAlgorithm::ChaCha20Poly1305),
            PLAINTEXT_SHORT,
        )
        .await;
        let truncated = &wire[..wire.len() - 5];
        let err = decrypt_wire(aead_key(), truncated)
            .await
            .expect_err("expected error for truncated wire");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn small_chunked_writes_roundtrip() {
        // Drive the encryptor with 1-byte writes to exercise the discriminator-pending path
        // and ensure no off-by-one in the buffer drain logic.
        let plaintext = PLAINTEXT_SHORT;

        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = SharedSink(shared.clone());
        let mut enc = StreamingAttachmentEncryptor::new(aes_key(), None, sink)
            .expect("encryptor construction");
        for byte in plaintext {
            enc.write_all(std::slice::from_ref(byte))
                .await
                .expect("byte-wise write");
        }
        enc.shutdown().await.expect("shutdown");
        let wire = shared.lock().expect("mutex poisoned").clone();

        // Read it back in small chunks too.
        let mut dec = StreamingAttachmentDecryptor::new(aes_key(), &wire[..])
            .expect("decryptor construction");
        let mut out = Vec::new();
        let mut tmp = [0u8; 7];
        loop {
            let n = dec.read(&mut tmp).await.expect("read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, plaintext);
    }

    #[tokio::test]
    async fn empty_plaintext_roundtrip_aes() {
        let wire = encrypt_via_shared(aes_key(), None, &[]).await;
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
        assert!(roundtripped.is_empty());
    }

    #[tokio::test]
    async fn empty_plaintext_roundtrip_chunked_aead_aes_gcm() {
        let wire = encrypt_via_shared(aead_key(), Some(AeadAlgorithm::Aes256Gcm), &[]).await;
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert!(roundtripped.is_empty());
    }

    #[tokio::test]
    async fn empty_plaintext_roundtrip_chunked_aead_chacha20_poly1305() {
        let wire = encrypt_via_shared(aead_key(), Some(AeadAlgorithm::ChaCha20Poly1305), &[]).await;
        let roundtripped = decrypt_wire(aead_key(), &wire).await.expect("decrypt");
        assert!(roundtripped.is_empty());
    }

    #[tokio::test]
    async fn aes_key_with_aead_algorithm_fails() {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = SharedSink(shared.clone());
        let result =
            StreamingAttachmentEncryptor::new(aes_key(), Some(AeadAlgorithm::Aes256Gcm), sink);
        match result {
            Err(CryptoError::OperationNotSupported(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("AES key + AEAD algorithm should fail"),
        }
    }

    #[tokio::test]
    async fn aead_key_without_algorithm_fails() {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = SharedSink(shared.clone());
        let result = StreamingAttachmentEncryptor::new(aead_key(), None, sink);
        match result {
            Err(CryptoError::OperationNotSupported(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("AEAD key without algorithm should fail"),
        }
    }

    // ----- AttachmentEncryptor / AttachmentDecryptor (chunked sync API) -----

    fn chunked_encrypt(key: &SymmetricCryptoKey, plaintext: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut enc = AttachmentEncryptor::new(key).expect("encryptor construction");
        let mut out = Vec::new();
        for chunk in plaintext.chunks(chunk_size.max(1)) {
            let bytes = enc.update(chunk).expect("update");
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(&enc.finalize().expect("finalize"));
        out
    }

    fn chunked_decrypt(
        key: SymmetricCryptoKey,
        wire: &[u8],
        chunk_size: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut dec = AttachmentDecryptor::new(key)?;
        let mut out = Vec::new();
        for chunk in wire.chunks(chunk_size.max(1)) {
            let bytes = dec.update(chunk)?;
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(&dec.finalize()?);
        Ok(out)
    }

    #[test]
    fn chunked_roundtrip_small() {
        let key = aes_key();
        let wire = chunked_encrypt(&key, PLAINTEXT_SHORT, 17);
        assert_eq!(wire[0], AES256_CBC_HMAC_LEGACY_STREAM_DISCRIMINATOR);
        let plaintext = chunked_decrypt(key, &wire, 11).expect("decrypt");
        assert_eq!(plaintext, PLAINTEXT_SHORT);
    }

    #[test]
    fn chunked_roundtrip_multi_kb() {
        let key = aes_key();
        let plaintext: Vec<u8> = (0..(32 * 1024 + 137)).map(|i| (i % 251) as u8).collect();
        let wire = chunked_encrypt(&key, &plaintext, 4096);
        let roundtripped = chunked_decrypt(key, &wire, 1024).expect("decrypt");
        assert_eq!(roundtripped, plaintext);
    }

    #[test]
    fn chunked_roundtrip_single_byte_chunks() {
        // Stress the discriminator handoff and per-byte buffering.
        let key = aes_key();
        let wire = chunked_encrypt(&key, PLAINTEXT_SHORT, 1);
        let plaintext = chunked_decrypt(key, &wire, 1).expect("decrypt");
        assert_eq!(plaintext, PLAINTEXT_SHORT);
    }

    #[test]
    fn chunked_decrypt_wrong_discriminator_fails() {
        let key = aes_key();
        let mut wire = chunked_encrypt(&key, PLAINTEXT_SHORT, 32);
        wire[0] = 0x07; // not 0x02
        let mut dec = AttachmentDecryptor::new(key).expect("decryptor construction");
        let err = dec.update(&wire).expect_err("must reject");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn chunked_decrypt_wrong_key_fails() {
        let enc_key = aes_key();
        let wrong_key = SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
            enc_key: Box::pin([2u8; 32].into()),
            mac_key: Box::pin([3u8; 32].into()),
        });
        let wire = chunked_encrypt(&enc_key, PLAINTEXT_SHORT, 32);
        let result = chunked_decrypt(wrong_key, &wire, 32);
        assert!(matches!(result, Err(CryptoError::Decrypt)));
    }

    #[test]
    fn chunked_decrypt_truncated_fails() {
        let key = aes_key();
        let wire = chunked_encrypt(&key, PLAINTEXT_SHORT, 32);
        // Lop off the last block — HMAC must fail to validate.
        let truncated = &wire[..wire.len() - 16];
        let result = chunked_decrypt(key, truncated, 32);
        assert!(matches!(result, Err(CryptoError::Decrypt)));
    }

    #[test]
    fn chunked_encryptor_wrong_key_type_fails() {
        let result = AttachmentEncryptor::new(&aead_key());
        assert!(matches!(result, Err(CryptoError::OperationNotSupported(_))));
    }

    #[test]
    fn chunked_decryptor_wrong_key_type_fails() {
        let result = AttachmentDecryptor::new(aead_key());
        assert!(matches!(result, Err(CryptoError::OperationNotSupported(_))));
    }

    #[test]
    fn chunked_encryptor_double_finalize_fails() {
        let key = aes_key();
        let mut enc = AttachmentEncryptor::new(&key).expect("encryptor");
        let _ = enc.finalize().expect("first finalize");
        assert!(matches!(enc.finalize(), Err(CryptoError::Decrypt)));
    }

    /// Interop check: bytes produced by the chunked sync encryptor can be
    /// decrypted by the AsyncRead-based `StreamingAttachmentDecryptor`.
    #[tokio::test]
    async fn chunked_encrypt_decrypts_with_async_decryptor() {
        let key = aes_key();
        let wire = chunked_encrypt(&key, PLAINTEXT_SHORT, 32);
        let roundtripped = decrypt_wire(key, &wire).await.expect("async decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }

    /// Interop check: bytes produced by the AsyncWrite-based
    /// `StreamingAttachmentEncryptor` can be decrypted by the chunked sync decryptor.
    #[tokio::test]
    async fn async_encrypt_decrypts_with_chunked_decryptor() {
        let key = aes_key();
        let wire = encrypt_via_shared(aes_key(), None, PLAINTEXT_SHORT).await;
        let roundtripped = chunked_decrypt(key, &wire, 32).expect("chunked decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }
}
