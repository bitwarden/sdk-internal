/// Large blob encryption and decryption needs to be streamed to keep performance reasonable.
/// This module implements streamed encryption, that can be plugged into other IO streaming
/// interfaces, to create a streamed encryption pipeline. Further, it defines the cryptography
/// behind attachments, with the legacy format for compatibility, and a new format that
/// supports random-access decryption, and has enhanced security properties.
use std::ops::Range;

pub(crate) mod aes256_cbc_hmac_legacy_stream;
mod large_memory_buffer;
mod streaming_attachment_cipher;

pub use streaming_attachment_cipher::{StreamingAttachmentDecryptor, StreamingAttachmentEncryptor};
use thiserror::Error;

/// Error returned by streaming-cipher constructors when the supplied key cannot be used with
/// that streaming cipher.
pub(crate) enum StreamCreationError {
    /// The supplied [`crate::SymmetricCryptoKey`] is not the variant this cipher expects.
    WrongKeyType,
}

/// Opaque error returned when a streaming decryptor fails. The reason (HMAC mismatch, invalid
/// padding, truncation) is intentionally not distinguished, to avoid leaking which check failed.
#[derive(Debug, Error)]
#[error("streaming decryption failed")]
pub(crate) struct StreamDecryptionError;

/// Opaque error returned when a streaming encryptor fails.
#[derive(Debug, Error)]
#[error("streaming encryption failed")]
pub(crate) struct StreamEncryptionError;

/// Outcome of feeding one chunk of plaintext to a [`StreamingEncryptor::update`].
pub(crate) enum ChunkEncryptionResult {
    /// The encryptor needs more input bytes before it can produce ciphertext.
    NeedMoreData,
    /// A chunk of the ciphertext is emitted, but the stream is not yet complete
    EncryptedChunk(Vec<u8>),
    /// The last chunk is emitted and the stream is completed. No more calls to `update` should be
    /// made after this.
    FinalEncryptedChunk(Vec<u8>),
    /// Encryption failed. Discard the entire stream.
    Error(StreamEncryptionError),
}

/// Outcome of feeding one chunk of wire bytes to a [`StreamingDecryptor::update`].
pub(crate) enum ChunkDecryptionResult {
    /// The decryptor needs more input bytes before it can produce plaintext.
    NeedMoreData,
    /// A chunk of decrypted plaintext. Whether this is already authenticated is
    /// implementation-defined: chunked-AEAD STREAM authenticates per chunk and these bytes
    /// can be trusted; AES-CBC + HMAC authenticates only at finalize, and these bytes must be
    /// treated as untrusted until the terminal [`Self::FinalDecryptedChunk`] is observed.
    DecryptedChunk(Vec<u8>),
    /// The final chunk of decrypted, authenticated plaintext.
    FinalDecryptedChunk(Vec<u8>),
    /// Decryption failed. Discard the entire stream.
    Error(StreamDecryptionError),
}

/// A symmetric streaming encryptor.
pub(crate) trait StreamingEncryptor: Sized {
    /// Pass in a chunk of any size of the stream. The encryptor buffers and emits as much
    /// ciphertext as it can. The caller signals the end of the stream by calling `update` with
    /// `last_block = true`.
    ///
    /// The encryptor *MAY* buffer the entire plaintext before emitting any ciphertext depending
    /// on the underlying algorithm implementation. In this case, the caller must
    /// keep calling update with an empty chunk until the final encrypted chunk is emitted.
    fn update(&mut self, plaintext_chunk: &[u8], last_block: bool) -> ChunkEncryptionResult;
}

/// A symmetric streaming decryptor.
pub(crate) trait StreamingDecryptor: Sized {
    /// Pass in a chunk of any size of the stream. The decryptor buffers and emits as much plaintext
    /// as it can. The caller signals the end of the stream by calling `update` with `last_block =
    /// true`. The decryptor emits the final chunk of plaintext and performs any final
    /// authentication checks if required. The caller MUST verify the presence of the final
    /// decrypted chunk before using the plaintext.
    fn update(&mut self, ciphertext_chunk: &[u8], last_block: bool) -> ChunkDecryptionResult;
}

/// A symmetric decryptor that supports random-access reads: given the complete encrypted
/// wire stream and a plaintext byte range, return only the plaintext covering that range.
///
/// Random access is only possible for wire formats whose framing lets the decryptor seek
/// into the ciphertext without reading the whole stream and whose chunks are individually
/// authenticated. Chunked-AEAD STREAM qualifies (fixed-size nonce prefix + fixed-size
/// chunks, each with its own AEAD tag); AES-256-CBC + HMAC-SHA256 does not, because its
/// trailing MAC covers the entire ciphertext and the stream must be read in full before
/// any bytes can be trusted.
#[allow(unused)]
pub(crate) trait RandomAccessDecryptor<R> {
    /// Error returned when authentication fails on any read chunk, the wire bytes are
    /// shorter than the framing requires, or `range` exceeds the plaintext length.
    type Error;

    /// Decrypt the plaintext bytes covering `range` from the encrypted `ciphertext` byte stream.
    async fn decrypt_range(
        &self,
        data_source: R,
        range: Range<usize>,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// A data source that supports random-access reads
#[allow(unused)]
pub(crate) trait RandomAccessDataSource {
    /// Error returned when authentication fails on any read chunk, the wire bytes are
    /// shorter than the framing requires, or `range` exceeds the plaintext length.
    type Error;

    /// Decrypt the plaintext bytes covering `range` from the encrypted `ciphertext` byte stream.
    async fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>, Self::Error>;
}
