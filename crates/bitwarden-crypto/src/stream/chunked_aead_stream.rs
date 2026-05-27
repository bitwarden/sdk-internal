//! # Chunked AEAD streaming cipher
//! Chunked AEAD streaming attachment cipher, built on top of the
//! [`aead-stream`](https://docs.rs/aead-stream) crate's BE32 STREAM construction
//! `https://eprint.iacr.org/2015/189.pdf`.
//!
//! ## Format
//! A stream starts with a header, which is the nonce prefix for the AEAD construction. The rest of the stream
//! consists of ciphertext chunks each with their own tag.
//! 
//! ## Overhead
//! Each 64 KiB chunk of plaintext incurs a 16-byte tag, so the ciphertext is ~0.025% larger than plaintext for large attachments.
//! 
//! ## Functional properties
//! 
//! Each chunk is authenticated independently and the encryption is dependent only on the counter and the key, but not
//! the previous block. Thus, we support secure random access decryption. Partial stream decryption is also fully authenticated,
//! so plaintext is usable before the entire stream is decrypted.

use std::ops::Range;

use aead_stream::{
    DecryptorBE32, EncryptorBE32,
    aead::{Aead, KeyInit, array::Array},
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hybrid_array::sizes::{U7, U12};
use rand::RngExt;

use super::{ChunkDecryptionResult, ChunkEncryptionResult, StreamCreationError};
use crate::{SymmetricCryptoKey, XChaCha20Poly1305Key};

/// Selects the AEAD primitive that STREAM is instantiated with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-256-GCM with a 12-byte nonce and 16-byte tag.
    Aes256Gcm,
    /// ChaCha20-Poly1305 with a 12-byte nonce and 16-byte tag.
    ChaCha20Poly1305,
}

/// Both AES-256-GCM and ChaCha20-Poly1305 use a 12-byte nonce; BE32 STREAM consumes the
/// trailing 5 bytes for its counter + last-block flag, leaving a 7-byte prefix on the wire.
const NONCE_PREFIX_SIZE: usize = 7;
const TAG_SIZE: usize = 16;
/// Plaintext bytes encrypted per intermediate STREAM chunk. The final chunk may be smaller.
const PLAINTEXT_CHUNK_SIZE: usize = 64 * 1024;
const CIPHERTEXT_CHUNK_SIZE: usize = PLAINTEXT_CHUNK_SIZE + TAG_SIZE;
const HEADER_LENGTH: usize = NONCE_PREFIX_SIZE;

type NoncePrefix = [u8; NONCE_PREFIX_SIZE];

enum DecryptorInitializeWithHeaderError {
    AlreadyInitialized,
}

// `decrypt_last` consumes the inner `DecryptorBE32`, so the state machine must be able to move
// out of the `Streaming` variant — which forbids a top-level `Drop` impl. Zeroization still
// happens at the field level: `XChaCha20Poly1305Key`'s inner key array is `ZeroizeOnDrop` via
// `hybrid_array`, and the AEAD ciphers inside the decryptor zeroize their keys on drop via
// the `zeroize` features of the `aes-gcm` and `chacha20poly1305` crates. The 7-byte STREAM
// nonce is non-secret.
// `Aes256Gcm`'s key schedule + GHASH state is ~1 KiB; boxing keeps the enum compact and
// avoids large-stack-copies between state transitions. `ChaCha20Poly1305`'s state is small
// enough to leave inline.
enum InnerDecryptor {
    Aes(Box<DecryptorBE32<Aes256Gcm>>),
    Cha(DecryptorBE32<ChaCha20Poly1305>),
}

impl InnerDecryptor {
    fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(dec) => dec.decrypt_next(ciphertext).map_err(|_| ()),
            Self::Cha(dec) => dec.decrypt_next(ciphertext).map_err(|_| ()),
        }
    }

    fn decrypt_last(self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(dec) => dec.decrypt_last(ciphertext).map_err(|_| ()),
            Self::Cha(dec) => dec.decrypt_last(ciphertext).map_err(|_| ()),
        }
    }
}

enum DecryptorState {
    Uninitialized {
        key: XChaCha20Poly1305Key,
        algorithm: AeadAlgorithm,
    },
    Streaming {
        decryptor: InnerDecryptor,
    },
    Done,
    Error,
}

impl DecryptorState {
    fn initialize(
        &mut self,
        nonce_prefix: NoncePrefix,
    ) -> Result<(), DecryptorInitializeWithHeaderError> {
        match self {
            Self::Uninitialized { key, algorithm } => {
                let nonce: Array<u8, U7> = nonce_prefix.into();
                let decryptor = match algorithm {
                    AeadAlgorithm::Aes256Gcm => {
                        let cipher = Aes256Gcm::new(&key.enc_key);
                        InnerDecryptor::Aes(Box::new(DecryptorBE32::from_aead(cipher, &nonce)))
                    }
                    AeadAlgorithm::ChaCha20Poly1305 => {
                        let cipher = ChaCha20Poly1305::new(&key.enc_key);
                        InnerDecryptor::Cha(DecryptorBE32::from_aead(cipher, &nonce))
                    }
                };
                *self = Self::Streaming { decryptor };
                Ok(())
            }
            _ => Err(DecryptorInitializeWithHeaderError::AlreadyInitialized),
        }
    }
}

/// Streaming chunked-AEAD (STREAM BE32) decryptor. The AEAD primitive (AES-256-GCM or
/// ChaCha20-Poly1305) is selected at construction time via [`AeadAlgorithm`]. Per-chunk tags
/// mean returned plaintext is already authenticated; truncation of the trailing chunk is
/// still only detected at `last_block = true`.
pub(crate) struct StreamingChunkedAeadDecryptor {
    // Wire bytes that have been passed in but not yet processed by the crypto implementation.
    // External chunks are concatenated here; the crypto state machine then drains exactly the
    // bytes it needs (the 7-byte header on the first pass, then `CIPHERTEXT_CHUNK_SIZE`-sized
    // intermediate chunks, with the trailing 0..=`CIPHERTEXT_CHUNK_SIZE` bytes consumed by
    // `decrypt_last` on `last_block = true`).
    buffer: Vec<u8>,
    decryptor_state: DecryptorState,
}

impl StreamingChunkedAeadDecryptor {
    pub(crate) fn try_new(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, StreamCreationError> {
        let key = match key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => return Err(StreamCreationError::WrongKeyType),
        };
        Ok(Self {
            buffer: Vec::new(),
            decryptor_state: DecryptorState::Uninitialized {
                key: key.clone(),
                algorithm,
            },
        })
    }
}

impl super::StreamingDecryptor for StreamingChunkedAeadDecryptor {
    fn update(&mut self, ciphertext_chunk: &[u8], last_block: bool) -> ChunkDecryptionResult {
        self.buffer.extend_from_slice(ciphertext_chunk);

        if matches!(
            self.decryptor_state,
            DecryptorState::Error | DecryptorState::Done
        ) {
            return ChunkDecryptionResult::Error;
        }

        // If the decryptor is uninitialized, it must be initialized before proceeding. The
        // nonce-prefix header lives at the start of the wire stream, so it accumulates in
        // `self.buffer` and is drained from there once enough bytes have arrived.
        if matches!(self.decryptor_state, DecryptorState::Uninitialized { .. }) {
            if self.buffer.len() < HEADER_LENGTH {
                if last_block {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
                return ChunkDecryptionResult::NeedMoreData;
            }
            let nonce_prefix: NoncePrefix = self
                .buffer
                .drain(..HEADER_LENGTH)
                .as_slice()
                .try_into()
                .expect("slice length checked by if condition");
            if self.decryptor_state.initialize(nonce_prefix).is_err() {
                self.decryptor_state = DecryptorState::Error;
                return ChunkDecryptionResult::Error;
            }
        }

        // Process intermediate chunks. While `last_block = false`, we know more data is coming,
        // so any whole CIPHERTEXT_CHUNK_SIZE bytes followed by at least one more byte cannot
        // be the final chunk and can be safely decrypted as intermediate. On `last_block =
        // true`, the loop drains intermediates until at most one full chunk remains for
        // `decrypt_last` to handle.
        let mut decrypted_data = Vec::new();
        if let DecryptorState::Streaming { decryptor } = &mut self.decryptor_state {
            while self.buffer.len() > CIPHERTEXT_CHUNK_SIZE {
                let ct: Vec<u8> = self.buffer.drain(..CIPHERTEXT_CHUNK_SIZE).collect();
                match decryptor.decrypt_next(ct.as_slice()) {
                    Ok(pt) => decrypted_data.extend_from_slice(&pt),
                    Err(_) => {
                        self.decryptor_state = DecryptorState::Error;
                        return ChunkDecryptionResult::Error;
                    }
                }
            }
        }

        if !last_block {
            if decrypted_data.is_empty() {
                return ChunkDecryptionResult::NeedMoreData;
            }
            return ChunkDecryptionResult::DecryptedChunk(decrypted_data);
        }

        // Final chunk. `decrypt_last` consumes the decryptor, so swap the state out via
        // `mem::replace` and reinsert `Done`/`Error` based on the outcome.
        let old_state = std::mem::replace(&mut self.decryptor_state, DecryptorState::Error);
        let DecryptorState::Streaming { decryptor } = old_state else {
            // Unreachable: we just verified we're past the uninitialized check and not in
            // Done/Error.
            return ChunkDecryptionResult::Error;
        };
        let final_chunk: Vec<u8> = std::mem::take(&mut self.buffer);
        if final_chunk.len() < TAG_SIZE {
            self.decryptor_state = DecryptorState::Error;
            return ChunkDecryptionResult::Error;
        }
        match decryptor.decrypt_last(final_chunk.as_slice()) {
            Ok(pt) => {
                decrypted_data.extend_from_slice(&pt);
                self.decryptor_state = DecryptorState::Done;
                ChunkDecryptionResult::FinalDecrypted(decrypted_data)
            }
            Err(_) => {
                self.decryptor_state = DecryptorState::Error;
                ChunkDecryptionResult::Error
            }
        }
    }
}

// See the comment on `InnerDecryptor` re: why this is not `ZeroizeOnDrop` and why `Aes` is
// boxed but `Cha` is not.
enum InnerEncryptor {
    Aes(Box<EncryptorBE32<Aes256Gcm>>),
    Cha(EncryptorBE32<ChaCha20Poly1305>),
}

impl InnerEncryptor {
    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(enc) => enc.encrypt_next(plaintext).map_err(|_| ()),
            Self::Cha(enc) => enc.encrypt_next(plaintext).map_err(|_| ()),
        }
    }

    fn encrypt_last(self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(enc) => enc.encrypt_last(plaintext).map_err(|_| ()),
            Self::Cha(enc) => enc.encrypt_last(plaintext).map_err(|_| ()),
        }
    }
}

enum EncryptorState {
    Streaming {
        encryptor: InnerEncryptor,
        nonce_prefix: NoncePrefix,
    },
    Done,
    Error,
}

/// Streaming chunked-AEAD (STREAM BE32) encryptor. The AEAD primitive (AES-256-GCM or
/// ChaCha20-Poly1305) is selected at construction time via [`AeadAlgorithm`]. The nonce
/// prefix is generated at construction time and emitted at the start of the wire byte stream
/// returned on the final [`ChunkEncryptionResult::FinalEncrypted`].
pub(crate) struct StreamingChunkedAeadEncryptor {
    // Plaintext bytes that have been passed in but not yet encrypted. Bytes are appended on
    // each `update` and drained `PLAINTEXT_CHUNK_SIZE` at a time via `encrypt_next`. On
    // `last_block = true`, any remaining bytes (0..=PLAINTEXT_CHUNK_SIZE) are encrypted via
    // `encrypt_last`.
    buffer: Vec<u8>,
    // Encrypted chunks awaiting the final flush. They are accumulated here so the terminal
    // `update` call can return `nonce_prefix || ciphertext` in a single payload.
    ciphertext_out: Vec<u8>,
    encryptor_state: EncryptorState,
}

impl StreamingChunkedAeadEncryptor {
    pub(crate) fn try_new(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, StreamCreationError> {
        let key = match key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => return Err(StreamCreationError::WrongKeyType),
        };

        let nonce_prefix: NoncePrefix = rand::rng().random();
        let nonce: Array<u8, U7> = nonce_prefix.into();
        let encryptor = match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&key.enc_key);
                InnerEncryptor::Aes(Box::new(EncryptorBE32::from_aead(cipher, &nonce)))
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&key.enc_key);
                InnerEncryptor::Cha(EncryptorBE32::from_aead(cipher, &nonce))
            }
        };

        Ok(Self {
            buffer: Vec::new(),
            ciphertext_out: Vec::new(),
            encryptor_state: EncryptorState::Streaming {
                encryptor,
                nonce_prefix,
            },
        })
    }
}

impl super::StreamingEncryptor for StreamingChunkedAeadEncryptor {
    fn update(&mut self, plaintext_chunk: &[u8], last_block: bool) -> ChunkEncryptionResult {
        if matches!(
            self.encryptor_state,
            EncryptorState::Error | EncryptorState::Done
        ) {
            return ChunkEncryptionResult::Error;
        }

        self.buffer.extend_from_slice(plaintext_chunk);

        // Encrypt all but the trailing chunk as intermediates. When `last_block = false`, we
        // don't yet know which chunk will be last, so we hold back up to one full plaintext
        // chunk's worth of bytes. When `last_block = true`, the same loop drains all but the
        // final chunk; the trailing 0..=PLAINTEXT_CHUNK_SIZE bytes go to `encrypt_last` below.
        if let EncryptorState::Streaming { encryptor, .. } = &mut self.encryptor_state {
            while self.buffer.len() > PLAINTEXT_CHUNK_SIZE {
                let pt: Vec<u8> = self.buffer.drain(..PLAINTEXT_CHUNK_SIZE).collect();
                match encryptor.encrypt_next(pt.as_slice()) {
                    Ok(ct) => self.ciphertext_out.extend_from_slice(&ct),
                    Err(_) => {
                        self.encryptor_state = EncryptorState::Error;
                        return ChunkEncryptionResult::Error;
                    }
                }
            }
        }

        if !last_block {
            return ChunkEncryptionResult::Buffered;
        }

        // Final chunk. `encrypt_last` consumes the encryptor; swap the state out and reinsert
        // `Done`/`Error` based on the outcome.
        let old_state = std::mem::replace(&mut self.encryptor_state, EncryptorState::Error);
        let EncryptorState::Streaming {
            encryptor,
            nonce_prefix,
        } = old_state
        else {
            return ChunkEncryptionResult::Error;
        };
        let final_pt: Vec<u8> = std::mem::take(&mut self.buffer);
        match encryptor.encrypt_last(final_pt.as_slice()) {
            Ok(ct) => {
                self.ciphertext_out.extend_from_slice(&ct);
                // Assemble the wire stream inline: `nonce_prefix || ciphertext`.
                let mut wire = Vec::with_capacity(HEADER_LENGTH + self.ciphertext_out.len());
                wire.extend_from_slice(&nonce_prefix);
                wire.append(&mut self.ciphertext_out);
                self.encryptor_state = EncryptorState::Done;
                ChunkEncryptionResult::FinalEncrypted { ciphertext: wire }
            }
            Err(_) => {
                self.encryptor_state = EncryptorState::Error;
                ChunkEncryptionResult::Error
            }
        }
    }
}

/// Random-access decryptor for the chunked-AEAD STREAM wire format. Holds the key and
/// algorithm but no per-stream state, so a single instance can serve many independent
/// `decrypt_range` calls against different (or the same) wire stream.
///
/// Each call reconstructs the per-chunk nonce from the wire's nonce prefix plus the
/// chunk index and last-block flag, then decrypts the chunks that overlap the requested
/// plaintext range using the underlying AEAD primitive directly. The STREAM construction
/// authenticates each chunk independently, so reading a subset of chunks is sound: any
/// returned bytes have been authenticated, and chunks outside the range are not read.
pub(crate) struct RandomAccessChunkedAeadDecryptor {
    key: XChaCha20Poly1305Key,
    algorithm: AeadAlgorithm,
}

impl RandomAccessChunkedAeadDecryptor {
    pub(crate) fn try_new(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, StreamCreationError> {
        let key = match key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => return Err(StreamCreationError::WrongKeyType),
        };
        Ok(Self {
            key: key.clone(),
            algorithm,
        })
    }
}

/// Parsed framing of a chunked-AEAD wire stream — derived from `wire.len()` and the
/// fixed-size header alone, no decryption performed.
struct ChunkedAeadWireLayout {
    nonce_prefix: NoncePrefix,
    /// Total number of chunks on the wire, including the final (possibly partial) one.
    /// Always >= 1.
    num_chunks: usize,
    /// Wire bytes occupied by the final chunk (TAG_SIZE..=CIPHERTEXT_CHUNK_SIZE).
    last_chunk_ct_len: usize,
    /// Plaintext length encoded by the wire.
    total_plaintext_len: usize,
}

impl ChunkedAeadWireLayout {
    fn parse(wire: &[u8]) -> Result<Self, ()> {
        if wire.len() < HEADER_LENGTH + TAG_SIZE {
            return Err(());
        }
        let nonce_prefix: NoncePrefix = wire[..HEADER_LENGTH].try_into().map_err(|_| ())?;
        let ct_len = wire.len() - HEADER_LENGTH;

        // Every intermediate chunk is exactly CIPHERTEXT_CHUNK_SIZE on the wire; the final
        // chunk is TAG_SIZE..=CIPHERTEXT_CHUNK_SIZE. So num_chunks =
        // (ct_len - 1) / CIPHERTEXT_CHUNK_SIZE + 1 and the trailing chunk occupies the
        // remainder.
        let num_chunks = (ct_len - 1) / CIPHERTEXT_CHUNK_SIZE + 1;
        let last_chunk_ct_len = ct_len - (num_chunks - 1) * CIPHERTEXT_CHUNK_SIZE;
        if last_chunk_ct_len < TAG_SIZE {
            return Err(());
        }
        // BE32 STREAM's position counter is u32; reject wire streams that would require a
        // larger counter rather than silently wrapping. (Encryption refuses to produce
        // these as well.)
        if num_chunks > u32::MAX as usize {
            return Err(());
        }
        let total_plaintext_len =
            (num_chunks - 1) * PLAINTEXT_CHUNK_SIZE + (last_chunk_ct_len - TAG_SIZE);
        Ok(Self {
            nonce_prefix,
            num_chunks,
            last_chunk_ct_len,
            total_plaintext_len,
        })
    }
}

fn chunk_nonce(prefix: &NoncePrefix, position: u32, last_block: bool) -> Array<u8, U12> {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_SIZE].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_SIZE..NONCE_PREFIX_SIZE + 4].copy_from_slice(&position.to_be_bytes());
    nonce[NONCE_PREFIX_SIZE + 4] = u8::from(last_block);
    nonce.into()
}

impl super::RandomAccessDecryptor for RandomAccessChunkedAeadDecryptor {
    type Error = ();

    fn decrypt_range(&self, wire: &[u8], range: Range<usize>) -> Result<Vec<u8>, ()> {
        if range.start > range.end {
            return Err(());
        }

        let layout = ChunkedAeadWireLayout::parse(wire)?;
        if range.end > layout.total_plaintext_len {
            return Err(());
        }
        if range.start == range.end {
            return Ok(Vec::new());
        }

        let start_chunk = range.start / PLAINTEXT_CHUNK_SIZE;
        let end_chunk = (range.end - 1) / PLAINTEXT_CHUNK_SIZE;
        let ct = &wire[HEADER_LENGTH..];
        let last_chunk_idx = layout.num_chunks - 1;

        // Decrypt each overlapping chunk and concatenate, then slice down to the exact
        // plaintext range. Constructing the AEAD cipher once per algorithm match keeps the
        // (relatively expensive) key schedule out of the per-chunk loop.
        let mut decrypted =
            Vec::with_capacity((end_chunk - start_chunk + 1) * PLAINTEXT_CHUNK_SIZE);
        match self.algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&self.key.enc_key);
                for chunk_idx in start_chunk..=end_chunk {
                    let is_last = chunk_idx == last_chunk_idx;
                    let ct_offset = chunk_idx * CIPHERTEXT_CHUNK_SIZE;
                    let ct_len = if is_last {
                        layout.last_chunk_ct_len
                    } else {
                        CIPHERTEXT_CHUNK_SIZE
                    };
                    let nonce = chunk_nonce(&layout.nonce_prefix, chunk_idx as u32, is_last);
                    let pt = cipher
                        .decrypt(&nonce, &ct[ct_offset..ct_offset + ct_len])
                        .map_err(|_| ())?;
                    decrypted.extend_from_slice(&pt);
                }
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&self.key.enc_key);
                for chunk_idx in start_chunk..=end_chunk {
                    let is_last = chunk_idx == last_chunk_idx;
                    let ct_offset = chunk_idx * CIPHERTEXT_CHUNK_SIZE;
                    let ct_len = if is_last {
                        layout.last_chunk_ct_len
                    } else {
                        CIPHERTEXT_CHUNK_SIZE
                    };
                    let nonce = chunk_nonce(&layout.nonce_prefix, chunk_idx as u32, is_last);
                    let pt = cipher
                        .decrypt(&nonce, &ct[ct_offset..ct_offset + ct_len])
                        .map_err(|_| ())?;
                    decrypted.extend_from_slice(&pt);
                }
            }
        }

        let local_start = range.start - start_chunk * PLAINTEXT_CHUNK_SIZE;
        let local_end = local_start + (range.end - range.start);
        Ok(decrypted[local_start..local_end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use hybrid_array::sizes::U32;

    use super::*;
    use crate::{
        KeyId,
        stream::{RandomAccessDecryptor, StreamingDecryptor, StreamingEncryptor},
    };

    const ENC_KEY: [u8; 32] = [0u8; 32];
    const PLAINTEXT: &[u8] = b"This is a test vector text for streaming encryption. It is long enough to require multiple chunks if PLAINTEXT_CHUNK_SIZE is set low.";

    fn test_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            key_id: KeyId::make(),
            enc_key: Pin::new(Box::new(Array::<u8, U32>::from(ENC_KEY))),
            supported_operations: vec![],
        })
    }

    fn encrypt_all(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        chunk_size: usize,
    ) -> Vec<u8> {
        let mut enc = StreamingChunkedAeadEncryptor::try_new(key, algorithm)
            .ok()
            .expect("encryptor construction");

        let mut wire: Vec<u8> = Vec::new();

        if plaintext.is_empty() {
            match enc.update(&[], true) {
                ChunkEncryptionResult::FinalEncrypted { ciphertext } => wire = ciphertext,
                _ => panic!("expected FinalEncrypted on empty input"),
            }
        } else {
            let total_chunks = plaintext.len().div_ceil(chunk_size);
            for (i, chunk) in plaintext.chunks(chunk_size).enumerate() {
                let last = i + 1 == total_chunks;
                match enc.update(chunk, last) {
                    ChunkEncryptionResult::Buffered => {
                        assert!(!last, "expected FinalEncrypted on last chunk");
                    }
                    ChunkEncryptionResult::FinalEncrypted { ciphertext } => {
                        assert!(last, "FinalEncrypted before last chunk");
                        wire = ciphertext;
                    }
                    ChunkEncryptionResult::Error => panic!("encrypt error"),
                }
            }
        }

        wire
    }

    fn decrypt_all(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
        wire: &[u8],
        chunk_size: usize,
    ) -> Vec<u8> {
        let mut dec = StreamingChunkedAeadDecryptor::try_new(key, algorithm)
            .ok()
            .expect("decryptor construction");

        let mut plaintext: Vec<u8> = Vec::new();
        let total_chunks = wire.len().div_ceil(chunk_size).max(1);
        for (i, chunk) in wire.chunks(chunk_size).enumerate() {
            let last = i + 1 == total_chunks;
            match dec.update(chunk, last) {
                ChunkDecryptionResult::NeedMoreData => {
                    assert!(!last, "NeedMoreData on last chunk");
                }
                ChunkDecryptionResult::DecryptedChunk(bytes) => {
                    plaintext.extend_from_slice(&bytes);
                }
                ChunkDecryptionResult::FinalDecrypted(bytes) => {
                    assert!(last, "FinalDecrypted before last chunk");
                    plaintext.extend_from_slice(&bytes);
                }
                ChunkDecryptionResult::Error => panic!("decrypt error"),
            }
        }
        plaintext
    }

    const ALGORITHMS: &[AeadAlgorithm] =
        &[AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305];

    #[test]
    fn streaming_encrypt_decrypt_roundtrip_single_chunk() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, 11);
            let roundtripped = decrypt_all(&key, algorithm, &wire, 9);
            assert_eq!(roundtripped, PLAINTEXT, "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn streaming_encrypt_decrypt_roundtrip_multi_chunk() {
        // Generate plaintext that crosses several STREAM chunk boundaries.
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let plaintext: Vec<u8> = (0..(PLAINTEXT_CHUNK_SIZE * 2 + 137))
                .map(|i| (i % 251) as u8)
                .collect();
            let wire = encrypt_all(&key, algorithm, &plaintext, 7919);
            let roundtripped = decrypt_all(&key, algorithm, &wire, 6151);
            assert_eq!(roundtripped, plaintext, "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn streaming_encrypt_decrypt_roundtrip_empty() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, &[], 64);
            // Wire is just the 7-byte header + 16-byte tag for empty final chunk.
            assert_eq!(
                wire.len(),
                HEADER_LENGTH + TAG_SIZE,
                "algorithm={algorithm:?}"
            );
            let roundtripped = decrypt_all(&key, algorithm, &wire, 7);
            assert!(roundtripped.is_empty(), "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn streaming_decrypt_with_truncated_ciphertext_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let truncated = &wire[..wire.len() - 10];
            let mut dec = StreamingChunkedAeadDecryptor::try_new(&key, algorithm)
                .ok()
                .expect("decryptor construction");
            let result = dec.update(truncated, true);
            assert!(
                matches!(result, ChunkDecryptionResult::Error),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn streaming_decrypt_with_modified_ciphertext_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let mut wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            // Flip a bit in the middle of the stream (past the header, inside the ciphertext).
            let flip_index = HEADER_LENGTH + 5;
            wire[flip_index] ^= 0b0000_0001;
            let mut dec = StreamingChunkedAeadDecryptor::try_new(&key, algorithm)
                .ok()
                .expect("decryptor construction");
            let result = dec.update(&wire, true);
            assert!(
                matches!(result, ChunkDecryptionResult::Error),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn streaming_decrypt_with_modified_header_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let mut wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            // Flip a bit in the nonce prefix.
            wire[3] ^= 0b0000_0001;
            let mut dec = StreamingChunkedAeadDecryptor::try_new(&key, algorithm)
                .ok()
                .expect("decryptor construction");
            let result = dec.update(&wire, true);
            assert!(
                matches!(result, ChunkDecryptionResult::Error),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn streaming_decrypt_truncated_to_just_header_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let header_only = &wire[..HEADER_LENGTH];
            let mut dec = StreamingChunkedAeadDecryptor::try_new(&key, algorithm)
                .ok()
                .expect("decryptor construction");
            let result = dec.update(header_only, true);
            assert!(
                matches!(result, ChunkDecryptionResult::Error),
                "algorithm={algorithm:?}",
            );
        }
    }

    fn random_access_decryptor(
        key: &SymmetricCryptoKey,
        algorithm: AeadAlgorithm,
    ) -> RandomAccessChunkedAeadDecryptor {
        RandomAccessChunkedAeadDecryptor::try_new(key, algorithm)
            .ok()
            .expect("random-access decryptor construction")
    }

    #[test]
    fn random_access_single_chunk_full_range() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            let out = dec
                .decrypt_range(&wire, 0..PLAINTEXT.len())
                .expect("decrypt full range");
            assert_eq!(out, PLAINTEXT, "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn random_access_single_chunk_subrange() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            let start = 5;
            let end = PLAINTEXT.len() - 7;
            let out = dec
                .decrypt_range(&wire, start..end)
                .expect("decrypt subrange");
            assert_eq!(out, &PLAINTEXT[start..end], "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn random_access_multi_chunk_spans_boundary() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let plaintext: Vec<u8> = (0..(PLAINTEXT_CHUNK_SIZE * 2 + 137))
                .map(|i| (i % 251) as u8)
                .collect();
            let wire = encrypt_all(&key, algorithm, &plaintext, 7919);
            let dec = random_access_decryptor(&key, algorithm);

            // Range entirely inside the first chunk.
            let r0 = 10..1000;
            assert_eq!(
                dec.decrypt_range(&wire, r0.clone())
                    .expect("inside chunk 0"),
                plaintext[r0],
                "algorithm={algorithm:?}",
            );

            // Range crossing the chunk_0 -> chunk_1 boundary.
            let r1 = (PLAINTEXT_CHUNK_SIZE - 50)..(PLAINTEXT_CHUNK_SIZE + 200);
            assert_eq!(
                dec.decrypt_range(&wire, r1.clone())
                    .expect("crosses 0->1 boundary"),
                plaintext[r1],
                "algorithm={algorithm:?}",
            );

            // Range crossing chunk_1 -> last chunk boundary, ending mid-last-chunk.
            let r2 = (PLAINTEXT_CHUNK_SIZE * 2 - 30)..(PLAINTEXT_CHUNK_SIZE * 2 + 100);
            assert_eq!(
                dec.decrypt_range(&wire, r2.clone())
                    .expect("crosses 1->last boundary"),
                plaintext[r2],
                "algorithm={algorithm:?}",
            );

            // Range entirely inside the (partial) last chunk.
            let r3 = (PLAINTEXT_CHUNK_SIZE * 2 + 10)..(PLAINTEXT_CHUNK_SIZE * 2 + 130);
            assert_eq!(
                dec.decrypt_range(&wire, r3.clone())
                    .expect("inside last chunk"),
                plaintext[r3],
                "algorithm={algorithm:?}",
            );

            // Whole plaintext.
            let full = 0..plaintext.len();
            assert_eq!(
                dec.decrypt_range(&wire, full.clone()).expect("full range"),
                plaintext,
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn random_access_empty_range_returns_empty() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            let out = dec.decrypt_range(&wire, 17..17).expect("empty range");
            assert!(out.is_empty(), "algorithm={algorithm:?}");
        }
    }

    #[test]
    fn random_access_range_out_of_bounds_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            assert!(
                dec.decrypt_range(&wire, 0..(PLAINTEXT.len() + 1)).is_err(),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn random_access_inverted_range_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            assert!(
                dec.decrypt_range(&wire, 10..5).is_err(),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn random_access_modified_chunk_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let plaintext: Vec<u8> = (0..(PLAINTEXT_CHUNK_SIZE + 50))
                .map(|i| (i % 251) as u8)
                .collect();
            let mut wire = encrypt_all(&key, algorithm, &plaintext, 4096);
            // Flip a bit inside the second (last) chunk.
            let flip = HEADER_LENGTH + CIPHERTEXT_CHUNK_SIZE + 3;
            wire[flip] ^= 0b0000_0001;
            let dec = random_access_decryptor(&key, algorithm);

            // Reading only the first chunk still succeeds — chunk authentication is local.
            let r_first = 0..10;
            assert!(
                dec.decrypt_range(&wire, r_first).is_ok(),
                "algorithm={algorithm:?}",
            );
            // Reading the tampered chunk fails.
            let r_tampered = PLAINTEXT_CHUNK_SIZE..(PLAINTEXT_CHUNK_SIZE + 10);
            assert!(
                dec.decrypt_range(&wire, r_tampered).is_err(),
                "algorithm={algorithm:?}",
            );
        }
    }

    #[test]
    fn random_access_truncated_wire_fails() {
        for &algorithm in ALGORITHMS {
            let key = test_key();
            let wire = encrypt_all(&key, algorithm, PLAINTEXT, PLAINTEXT.len());
            let dec = random_access_decryptor(&key, algorithm);
            // Truncate past the tag.
            let truncated = &wire[..wire.len() - 5];
            assert!(
                dec.decrypt_range(truncated, 0..10).is_err(),
                "algorithm={algorithm:?}",
            );
        }
    }
}
