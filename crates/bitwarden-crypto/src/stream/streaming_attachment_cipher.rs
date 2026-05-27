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
//! `0x02` matches the long-standing `EncString::Aes256Cbc_HmacSha256_B64 = 2` numbering.

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

enum HeaderDiscriminator {
    Aes256CbcHmacLegacyStream = 0x02,
}

impl From<HeaderDiscriminator> for u8 {
    fn from(value: HeaderDiscriminator) -> Self {
        value as u8
    }
}

struct UnknownDiscriminator;

impl TryFrom<u8> for HeaderDiscriminator {
    type Error = UnknownDiscriminator;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x02 => Ok(HeaderDiscriminator::Aes256CbcHmacLegacyStream),
            _ => Err(UnknownDiscriminator),
        }
    }
}

const READ_SCRATCH_SIZE: usize = 8 * 1024;

// An enum representing the state of the streaming attachment decryptor. This is a state machine
// for attachment stream parsing. As soon as the header bytes are parsed that discriminate the
// encryption type, the state transitions to the appropriate streaming decryptor.
enum StreamDecryptorState {
    /// First byte of the wire has not yet been observed.
    NeedDiscriminator { key: SymmetricCryptoKey },
    Aes256CbcHmacLegacyStream {
        decryptor: Box<StreamingAes256CbcHmacDecryptor>,
    },
    /// Underlying decryptor finalized successfully; remaining plaintext is in `plaintext_buf`.
    Done,
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
                inner_eof: false,
            }),
            _ => Err(CryptoError::OperationNotSupported(
                crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
            )),
        }
    }

    /// Drains the plaintext buffer into the passed in `ReadBuf`. Returns `true` if any bytes were
    /// drained.
    fn drain_plaintext_into(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let bytes_to_copy = std::cmp::min(buf.remaining(), self.plaintext_buf.len());
        // All bytes that are available already
        if bytes_to_copy == 0 {
            return false;
        }

        buf.put_slice(&self.plaintext_buf[..bytes_to_copy]);
        self.plaintext_buf.drain(..bytes_to_copy);
        true
    }

    fn feed_bytes_to_decryptor(&mut self, mut data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if let StreamDecryptorState::NeedDiscriminator { key } = &self.state {
            let discriminator_byte = HeaderDiscriminator::try_from(data[0]).map_err(|_| {
                io::Error::other("streaming attachment: unknown header discriminator byte")
            })?;
            data = &data[1..];

            match discriminator_byte {
                HeaderDiscriminator::Aes256CbcHmacLegacyStream => {
                    let decryptor =
                        StreamingAes256CbcHmacDecryptor::try_new(key).map_err(|_| {
                            io::Error::other(
                                "streaming attachment: key does not match discriminator 0x02",
                            )
                        })?;
                    self.state = StreamDecryptorState::Aes256CbcHmacLegacyStream {
                        decryptor: Box::new(decryptor),
                    };
                }
            }
        }

        if data.is_empty() {
            return Ok(());
        }

        match &mut self.state {
            StreamDecryptorState::Aes256CbcHmacLegacyStream { decryptor: dec } => {
                match dec.update(data, false) {
                    ChunkDecryptionResult::NeedMoreData => Ok(()),
                    ChunkDecryptionResult::DecryptedChunk(bytes) => {
                        self.plaintext_buf.extend_from_slice(&bytes);
                        Ok(())
                    }
                    ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                        self.plaintext_buf.extend_from_slice(&bytes);
                        self.state = StreamDecryptorState::Done;
                        Ok(())
                    }
                    ChunkDecryptionResult::Error => {
                        self.state = StreamDecryptorState::Error;
                        Err(io::Error::other(
                            "streaming attachment: AES-CBC-HMAC decryption error",
                        ))
                    }
                }
            }
            StreamDecryptorState::Error | StreamDecryptorState::Done => Ok(()),
            StreamDecryptorState::NeedDiscriminator { .. } => unreachable!("handled above"),
        }
    }

    fn finalize_underlying(&mut self) -> io::Result<()> {
        match std::mem::replace(&mut self.state, StreamDecryptorState::Error) {
            StreamDecryptorState::NeedDiscriminator { .. } => Err(io::Error::other(
                "streaming attachment: truncated before discriminator",
            )),
            StreamDecryptorState::Aes256CbcHmacLegacyStream { decryptor: mut dec } => {
                match dec.update(&[], true) {
                    ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                        self.plaintext_buf.extend_from_slice(&bytes);
                        self.state = StreamDecryptorState::Done;
                        Ok(())
                    }
                    _ => Err(io::Error::other(
                        "streaming attachment: AES-CBC-HMAC finalize failed (truncated or tampered)",
                    )),
                }
            }
            StreamDecryptorState::Done => {
                self.state = StreamDecryptorState::Done;
                Ok(())
            }
            StreamDecryptorState::Error => {
                Err(io::Error::other("streaming attachment: decryption error"))
            }
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
            // Drain decrypted plaintext into the caller's buffer first.
            if this.drain_plaintext_into(buf) {
                return Poll::Ready(Ok(()));
            }

            // If we already errored, surface it.
            if matches!(this.state, StreamDecryptorState::Error) {
                return Poll::Ready(Err(io::Error::other(
                    "streaming attachment: decryption error",
                )));
            }

            // If we're done draining and the underlying stream is finalized, signal EOF.
            if matches!(this.state, StreamDecryptorState::Done) {
                return Poll::Ready(Ok(()));
            }

            // If the inner reader has hit EOF, run the terminal finalize and loop to drain.
            if this.inner_eof {
                if let Err(e) = this.finalize_underlying() {
                    return Poll::Ready(Err(e));
                }
                continue;
            }

            // Otherwise, pull more bytes from the inner reader, and feed them to the decryptor
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
                    } else if let Err(e) = this.feed_bytes_to_decryptor(filled) {
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
/// wire stream to `W`. The cipher is selected by the [`SymmetricCryptoKey`] variant. The
/// 1-byte discriminator is emitted before any plaintext is encrypted.
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
    /// Construct an encryptor. The corresponding discriminator byte is queued as the first
    /// wire byte.
    pub fn new(key: SymmetricCryptoKey, inner: W) -> Result<Self, CryptoError> {
        let (state, discriminator): (StreamEncryptorState, HeaderDiscriminator) = match &key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => {
                let encryptor = StreamingAes256CbcHmacEncryptor::try_new(&key).map_err(|_| {
                    CryptoError::OperationNotSupported(
                        crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
                    )
                })?;
                (
                    StreamEncryptorState::Aes256CbcHmacLegacyStream {
                        encryptor: Box::new(encryptor),
                    },
                    HeaderDiscriminator::Aes256CbcHmacLegacyStream,
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
            pending_write: vec![discriminator.into()],
            pending_head: 0,
        })
    }
}

impl<W: AsyncWrite + Unpin> StreamingAttachmentEncryptor<W> {
    // Attempt to drain the pending write buffer to the inner writer.
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
        if matches!(
            this.state,
            StreamEncryptorState::Finalized | StreamEncryptorState::Done
        ) {
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
            StreamEncryptorState::Aes256CbcHmacLegacyStream { encryptor: enc } => {
                enc.update(buf, false)
            }
            _ => unreachable!("state checked above"),
        };

        match result {
            ChunkEncryptionResult::NeedMoreData => Poll::Ready(Ok(buf.len())),
            ChunkEncryptionResult::EncryptedChunk(bytes) => {
                this.pending_write = bytes;
                this.pending_head = 0;
                Poll::Ready(Ok(buf.len()))
            }
            ChunkEncryptionResult::FinalEncryptedChunk(bytes) => {
                this.pending_write = bytes;
                this.pending_head = 0;
                this.state = StreamEncryptorState::Finalized;
                Poll::Ready(Ok(buf.len()))
            }
            ChunkEncryptionResult::Error => {
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

        // Drain any pending bytes
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }

        // If we haven't finalized yet, drain all output from the encryptor.
        if matches!(
            this.state,
            StreamEncryptorState::Aes256CbcHmacLegacyStream { .. }
        ) {
            let old = std::mem::replace(&mut this.state, StreamEncryptorState::Error);
            let StreamEncryptorState::Aes256CbcHmacLegacyStream { encryptor: mut enc } = old else {
                unreachable!("matched above");
            };

            let mut wire = Vec::new();
            loop {
                match enc.update(&[], true) {
                    ChunkEncryptionResult::EncryptedChunk(bytes) => wire.extend_from_slice(&bytes),
                    ChunkEncryptionResult::FinalEncryptedChunk(bytes) => {
                        wire.extend_from_slice(&bytes);
                        break;
                    }
                    ChunkEncryptionResult::NeedMoreData | ChunkEncryptionResult::Error => {
                        return Poll::Ready(Err(io::Error::other(
                            "streaming attachment: AES-CBC-HMAC finalize failed",
                        )));
                    }
                }
            }

            this.pending_write = wire;
            this.pending_head = 0;
            this.state = StreamEncryptorState::Finalized;
        }

        // Drain the finalized wire payload to the inner writer.
        if this.poll_drain_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if matches!(this.state, StreamEncryptorState::Error) {
            return Poll::Ready(Err(io::Error::other(
                "streaming attachment: encryptor in error state",
            )));
        }

        // Shut down the inner writer.
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

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::Aes256CbcHmacKey;

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

    /// Drive the encryptor to completion against an in-memory sink and return the produced wire.
    async fn encrypt_via_shared(key: SymmetricCryptoKey, plaintext: &[u8]) -> Vec<u8> {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = SharedSink(shared.clone());
        let mut enc = StreamingAttachmentEncryptor::new(key, sink).expect("encryptor construction");
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
        let wire = encrypt_via_shared(aes_key(), PLAINTEXT_SHORT).await;
        assert_eq!(
            wire.first().copied(),
            Some(HeaderDiscriminator::Aes256CbcHmacLegacyStream.into()),
            "wire should start with the AES-CBC-HMAC discriminator"
        );
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
        assert_eq!(roundtripped, PLAINTEXT_SHORT);
    }

    #[tokio::test]
    async fn aes_cbc_hmac_roundtrip_1_mib() {
        // Bigger plaintext crossing many CBC blocks.
        let plaintext: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let wire = encrypt_via_shared(aes_key(), &plaintext).await;
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
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
    async fn truncated_wire_fails_aes() {
        let wire = encrypt_via_shared(aes_key(), PLAINTEXT_SHORT).await;
        let truncated = &wire[..wire.len() - 10];
        let err = decrypt_wire(aes_key(), truncated)
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
        let mut enc =
            StreamingAttachmentEncryptor::new(aes_key(), sink).expect("encryptor construction");
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
        let wire = encrypt_via_shared(aes_key(), &[]).await;
        let roundtripped = decrypt_wire(aes_key(), &wire).await.expect("decrypt");
        assert!(roundtripped.is_empty());
    }
}
