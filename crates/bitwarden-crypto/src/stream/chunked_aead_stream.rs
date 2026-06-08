//! # Aead-Stream Format
//! Aead-Stream is a scalable format for encrypting large files performantly.
//!
//! ## Format
//! The stream consists of a header, along with a ciphertext.
//! ```text
//! Ciphertext = HEADER_LEN (BE) || HEADER (CBOR) || STREAM
//!
//! Header = {
//!   version: integer, // 1
//!   algorithm: "aes-gcm", "chacha20-poly1305",
//!   key_id: bytes, // COSE key id of the encrypting key
//!   chunk_size: integer, // 64KiB = 1024 * 64
//!   iv: bytes,
//! }
//!
//! STREAM = CHUNK_1 || CHUNK_2 || ... || CHUNK_N
//! CHUNK = CIPHERTEXT || TAG
//! ```
//!
//! Built on top of the [`aead-stream`](https://docs.rs/aead-stream) crate's BE32 STREAM
//! construction <https://eprint.iacr.org/2015/189.pdf>. Each chunk is authenticated
//! independently, so partial / random-access reads are sound, and per-chunk plaintext is
//! already authenticated when it is returned.

use std::ops::Range;

use aead_stream::{
    DecryptorBE32, EncryptorBE32,
    aead::{Aead, KeyInit, array::Array},
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use ciborium::Value;
use hybrid_array::sizes::{U7, U12, U32};
use rand::RngExt;
use subtle::ConstantTimeEq;

use super::{
    ChunkDecryptionResult, ChunkEncryptionResult, RandomAccessDataSource, StreamCreationError,
};
use crate::{SymmetricCryptoKey, keys::KeyId};

/// The 256-bit key material plus key id needed to instantiate a stream AEAD. Extracted from the
/// AES-256-GCM / ChaCha20-Poly1305 [`SymmetricCryptoKey`] variants; the variant determines the
/// algorithm.
struct StreamKey {
    algorithm: AeadAlgorithm,
    key_id: KeyId,
    enc_key: std::pin::Pin<Box<Array<u8, U32>>>,
}

impl StreamKey {
    fn try_from_symmetric(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        match key {
            SymmetricCryptoKey::Aes256GcmKey(k) => Ok(Self {
                algorithm: AeadAlgorithm::Aes256Gcm,
                key_id: k.key_id.clone(),
                enc_key: k.enc_key.clone(),
            }),
            SymmetricCryptoKey::ChaCha20Poly1305Key(k) => Ok(Self {
                algorithm: AeadAlgorithm::ChaCha20Poly1305,
                key_id: k.key_id.clone(),
                enc_key: k.enc_key.clone(),
            }),
            _ => Err(StreamCreationError::WrongKeyType),
        }
    }
}

/// Selects the AEAD primitive that STREAM is instantiated with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AeadAlgorithm {
    /// AES-256-GCM with a 12-byte nonce and 16-byte tag.
    Aes256Gcm,
    /// ChaCha20-Poly1305 with a 12-byte nonce and 16-byte tag.
    ChaCha20Poly1305,
}

const ALG_AES_GCM: &str = "aes-gcm";
const ALG_CHACHA20_POLY1305: &str = "chacha20-poly1305";

impl AeadAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            AeadAlgorithm::Aes256Gcm => ALG_AES_GCM,
            AeadAlgorithm::ChaCha20Poly1305 => ALG_CHACHA20_POLY1305,
        }
    }
    fn try_from_str(s: &str) -> Option<Self> {
        match s {
            ALG_AES_GCM => Some(AeadAlgorithm::Aes256Gcm),
            ALG_CHACHA20_POLY1305 => Some(AeadAlgorithm::ChaCha20Poly1305),
            _ => None,
        }
    }
}

/// BE32 STREAM consumes the trailing 5 bytes of the AEAD's 12-byte nonce for its counter +
/// last-block flag, leaving a 7-byte prefix on the wire.
const NONCE_PREFIX_SIZE: usize = 7;
const TAG_SIZE: usize = 16;
/// Default plaintext bytes encrypted per intermediate STREAM chunk. The encryptor emits this
/// chunk size; the decryptor honors whatever is in the wire header.
const DEFAULT_PLAINTEXT_CHUNK_SIZE: usize = 64 * 1024;
/// `u32`-BE prefix giving the length of the CBOR header.
const HEADER_LEN_PREFIX_SIZE: usize = 4;
const HEADER_VERSION: u64 = 1;

const KEY_VERSION: &str = "version";
const KEY_ALGORITHM: &str = "algorithm";
const KEY_KEY_ID: &str = "key_id";
const KEY_CHUNK_SIZE: &str = "chunk_size";
const KEY_IV: &str = "iv";

type NoncePrefix = [u8; NONCE_PREFIX_SIZE];

/// Parsed CBOR header.
pub(crate) struct StreamHeader {
    algorithm: AeadAlgorithm,
    key_id: KeyId,
    chunk_size: u64,
    iv: NoncePrefix,
}

impl StreamHeader {
    fn encode(&self) -> Vec<u8> {
        let map = Value::Map(vec![
            (
                Value::Text(KEY_VERSION.into()),
                Value::Integer(HEADER_VERSION.into()),
            ),
            (
                Value::Text(KEY_ALGORITHM.into()),
                Value::Text(self.algorithm.as_str().into()),
            ),
            (
                Value::Text(KEY_KEY_ID.into()),
                Value::Bytes((&self.key_id).into()),
            ),
            (
                Value::Text(KEY_CHUNK_SIZE.into()),
                Value::Integer(self.chunk_size.into()),
            ),
            (Value::Text(KEY_IV.into()), Value::Bytes(self.iv.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).expect("CBOR encoding cannot fail");
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, ()> {
        let value: Value = ciborium::de::from_reader(bytes).map_err(|_| ())?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return Err(()),
        };

        let mut version: Option<u64> = None;
        let mut algorithm: Option<AeadAlgorithm> = None;
        let mut key_id: Option<KeyId> = None;
        let mut chunk_size: Option<u64> = None;
        let mut iv: Option<NoncePrefix> = None;
        for (k, v) in entries {
            let Value::Text(key) = k else { continue };
            match key.as_str() {
                KEY_VERSION => version = read_u64(&v),
                KEY_ALGORITHM => {
                    algorithm = match v {
                        Value::Text(s) => AeadAlgorithm::try_from_str(&s),
                        _ => None,
                    }
                }
                KEY_KEY_ID => {
                    key_id = match v {
                        Value::Bytes(b) => KeyId::try_from(b.as_slice()).ok(),
                        _ => None,
                    }
                }
                KEY_CHUNK_SIZE => chunk_size = read_u64(&v),
                KEY_IV => {
                    iv = match v {
                        Value::Bytes(b) => NoncePrefix::try_from(b.as_slice()).ok(),
                        _ => None,
                    }
                }
                _ => {}
            }
        }

        if version != Some(HEADER_VERSION) {
            return Err(());
        }
        let header = Self {
            algorithm: algorithm.ok_or(())?,
            key_id: key_id.ok_or(())?,
            chunk_size: chunk_size.ok_or(())?,
            iv: iv.ok_or(())?,
        };
        if header.chunk_size == 0 || header.chunk_size > usize::MAX as u64 {
            return Err(());
        }
        Ok(header)
    }
}

impl std::fmt::Debug for StreamHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHeader")
            .field("version", &HEADER_VERSION)
            .field("algorithm", &self.algorithm.as_str())
            .field("key_id", &hex::encode(self.key_id.as_slice()))
            .field("chunk_size", &self.chunk_size)
            .field("iv", &hex::encode(self.iv))
            .finish()
    }
}

/// Parse the wire header from the first bytes of a chunked-AEAD stream, for inspection/logging.
///
/// `prefix` must contain at least the 4-byte `HEADER_LEN` prefix followed by the full CBOR
/// header (the header is small — well under 500 bytes — so the first 500 bytes of any stream
/// are sufficient). No key material is involved, so no key is required. Returns the parsed
/// [`StreamHeader`], which can be `{:?}`-formatted to show the algorithm, key id, chunk size,
/// and IV.
#[allow(unused)]
pub(crate) fn inspect_stream_header(prefix: &[u8]) -> Result<StreamHeader, ()> {
    if prefix.len() < HEADER_LEN_PREFIX_SIZE {
        return Err(());
    }
    let len_bytes: [u8; HEADER_LEN_PREFIX_SIZE] = prefix[..HEADER_LEN_PREFIX_SIZE]
        .try_into()
        .expect("slice length checked above");
    let header_len = u32::from_be_bytes(len_bytes) as usize;
    let header_end = HEADER_LEN_PREFIX_SIZE.checked_add(header_len).ok_or(())?;
    if prefix.len() < header_end {
        return Err(());
    }
    StreamHeader::decode(&prefix[HEADER_LEN_PREFIX_SIZE..header_end])
}

fn read_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// Derived from `header.chunk_size` + the length of the ciphertext region on the wire, no
/// decryption performed.
struct StreamLayout {
    /// Plaintext bytes per intermediate chunk (header `chunk_size`).
    plaintext_chunk_size: usize,
    /// Wire bytes per intermediate chunk (`plaintext_chunk_size + TAG_SIZE`).
    ciphertext_chunk_size: usize,
    /// Number of chunks on the wire, including the final (possibly partial) one. >= 1.
    num_chunks: usize,
    /// Wire bytes occupied by the final chunk (TAG_SIZE..=ciphertext_chunk_size).
    last_chunk_ct_len: usize,
    /// Total decrypted plaintext length, derived from the wire layout. Used for range-bound
    /// validation.
    plaintext_length: usize,
}

impl StreamLayout {
    /// Reconstruct the chunk layout from the wire. `ciphertext_region_len` is the number of
    /// bytes following the header (i.e. the STREAM portion). Every chunk — including the last —
    /// carries a 16-byte tag, so the layout is fully determined by the region length and the
    /// per-chunk size.
    fn from_wire(header: &StreamHeader, ciphertext_region_len: usize) -> Result<Self, ()> {
        let plaintext_chunk_size: usize = usize::try_from(header.chunk_size).map_err(|_| ())?;
        if plaintext_chunk_size == 0 {
            return Err(());
        }
        let ciphertext_chunk_size = plaintext_chunk_size.checked_add(TAG_SIZE).ok_or(())?;

        // The smallest valid stream is a single chunk holding just the AEAD tag (empty
        // plaintext). Anything shorter is malformed.
        if ciphertext_region_len < TAG_SIZE {
            return Err(());
        }
        let num_chunks = ciphertext_region_len.div_ceil(ciphertext_chunk_size);
        // BE32 STREAM's position counter is u32; reject wire streams that would require a
        // larger counter rather than silently wrapping.
        if num_chunks > u32::MAX as usize {
            return Err(());
        }
        let last_chunk_ct_len = ciphertext_region_len - (num_chunks - 1) * ciphertext_chunk_size;
        // The final chunk must contain at least a tag, and no more than a full chunk.
        if last_chunk_ct_len < TAG_SIZE || last_chunk_ct_len > ciphertext_chunk_size {
            return Err(());
        }
        let plaintext_length =
            (num_chunks - 1) * plaintext_chunk_size + (last_chunk_ct_len - TAG_SIZE);
        Ok(Self {
            plaintext_chunk_size,
            ciphertext_chunk_size,
            num_chunks,
            last_chunk_ct_len,
            plaintext_length,
        })
    }
}

// `decrypt_last` consumes the inner `DecryptorBE32`, so the state machine must be able to move
// out of the `Streaming` variant — which forbids a top-level `Drop` impl. Zeroization still
// happens at the field level: the [`StreamKey`]'s inner key array is `ZeroizeOnDrop` via
// `hybrid_array`, and the AEAD ciphers inside the decryptor zeroize their keys on drop via
// the `zeroize` features of the `aes-gcm` and `chacha20poly1305` crates. The 7-byte STREAM
// nonce is non-secret.
// `Aes256Gcm`'s key schedule + GHASH state is ~1 KiB; boxing keeps the enum compact and
// avoids large-stack-copies between state transitions. `ChaCha20Poly1305`'s state is small
// enough to leave inline.
enum InnerDecryptor {
    Aes256Gcm(Box<DecryptorBE32<Aes256Gcm>>),
    ChaCha20Poly1305(Box<DecryptorBE32<ChaCha20Poly1305>>),
}

impl InnerDecryptor {
    fn new(enc_key: &Array<u8, U32>, algorithm: AeadAlgorithm, nonce: &Array<u8, U7>) -> Self {
        match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(enc_key);
                InnerDecryptor::Aes256Gcm(Box::new(DecryptorBE32::from_aead(cipher, nonce)))
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(enc_key);
                InnerDecryptor::ChaCha20Poly1305(Box::new(DecryptorBE32::from_aead(cipher, nonce)))
            }
        }
    }

    fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes256Gcm(dec) => dec.decrypt_next(ciphertext).map_err(|_| ()),
            Self::ChaCha20Poly1305(dec) => dec.decrypt_next(ciphertext).map_err(|_| ()),
        }
    }

    fn decrypt_last(self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes256Gcm(dec) => dec.decrypt_last(ciphertext).map_err(|_| ()),
            Self::ChaCha20Poly1305(dec) => dec.decrypt_last(ciphertext).map_err(|_| ()),
        }
    }
}

enum DecryptorState {
    /// Have not yet read the 4-byte HEADER_LEN prefix.
    NeedHeaderLen,
    /// Have HEADER_LEN; still reading the CBOR header body.
    NeedHeader {
        header_len: usize,
    },
    Streaming {
        decryptor: InnerDecryptor,
        ciphertext_chunk_size: usize,
    },
    Done,
    Error,
}

/// Streaming chunked-AEAD (STREAM BE32) decryptor. The AEAD primitive and IV are read from the
/// wire header at the start of the stream; the key supplied at construction must match.
/// Per-chunk tags mean returned plaintext is already authenticated; truncation of the trailing
/// chunk is only detected at `last_block = true`.
pub(crate) struct StreamingChunkedAeadDecryptor {
    // Wire bytes that have been passed in but not yet processed. External chunks are
    // concatenated here; the crypto state machine then drains exactly the bytes it needs (the
    // header length prefix, then the CBOR header, then `ciphertext_chunk_size`-sized
    // intermediate chunks, with the trailing 0..=`ciphertext_chunk_size` bytes consumed by
    // `decrypt_last` on `last_block = true`).
    buffer: Vec<u8>,
    key: StreamKey,
    decryptor_state: DecryptorState,
}

impl StreamingChunkedAeadDecryptor {
    pub(crate) fn try_new(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        Ok(Self {
            buffer: Vec::new(),
            key: StreamKey::try_from_symmetric(key)?,
            decryptor_state: DecryptorState::NeedHeaderLen,
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

        // Parse the HEADER_LEN prefix once enough bytes are available.
        if matches!(self.decryptor_state, DecryptorState::NeedHeaderLen) {
            if self.buffer.len() < HEADER_LEN_PREFIX_SIZE {
                if last_block {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
                return ChunkDecryptionResult::NeedMoreData;
            }
            let len_bytes: [u8; HEADER_LEN_PREFIX_SIZE] = self
                .buffer
                .drain(..HEADER_LEN_PREFIX_SIZE)
                .as_slice()
                .try_into()
                .expect("slice length checked by if condition");
            let header_len = u32::from_be_bytes(len_bytes) as usize;
            self.decryptor_state = DecryptorState::NeedHeader { header_len };
        }

        // Parse the CBOR header once enough bytes are available.
        if let DecryptorState::NeedHeader { header_len } = self.decryptor_state {
            if self.buffer.len() < header_len {
                if last_block {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
                return ChunkDecryptionResult::NeedMoreData;
            }
            let header_bytes: Vec<u8> = self.buffer.drain(..header_len).collect();
            let header = match StreamHeader::decode(&header_bytes) {
                Ok(h) => h,
                Err(_) => {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
            };
            // The wire header must agree with the supplied key on both the AEAD primitive and
            // the key id; otherwise we'd be decrypting with the wrong key/algorithm.
            if header.algorithm != self.key.algorithm
                || !bool::from(header.key_id.ct_eq(&self.key.key_id))
            {
                self.decryptor_state = DecryptorState::Error;
                return ChunkDecryptionResult::Error;
            }
            let plaintext_chunk_size = match usize::try_from(header.chunk_size) {
                Ok(s) if s > 0 => s,
                _ => {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
            };
            let Some(ciphertext_chunk_size) = plaintext_chunk_size.checked_add(TAG_SIZE) else {
                self.decryptor_state = DecryptorState::Error;
                return ChunkDecryptionResult::Error;
            };
            let nonce: Array<u8, U7> = header.iv.into();
            let decryptor = InnerDecryptor::new(&self.key.enc_key, header.algorithm, &nonce);
            self.decryptor_state = DecryptorState::Streaming {
                decryptor,
                ciphertext_chunk_size,
            };
        }

        // Process intermediate chunks. While `last_block = false`, we know more data is coming,
        // so any whole `ciphertext_chunk_size` bytes followed by at least one more byte cannot
        // be the final chunk and can be safely decrypted as intermediate. On `last_block =
        // true`, the loop drains intermediates until at most one full chunk remains for
        // `decrypt_last` to handle.
        let mut decrypted_data = Vec::new();
        if let DecryptorState::Streaming {
            decryptor,
            ciphertext_chunk_size,
        } = &mut self.decryptor_state
        {
            while self.buffer.len() > *ciphertext_chunk_size {
                let ct: Vec<u8> = self.buffer.drain(..*ciphertext_chunk_size).collect();
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

        // Final chunk. `decrypt_last` consumes the decryptor, so swap the state out and
        // reinsert `Done`/`Error` based on the outcome.
        let old_state = std::mem::replace(&mut self.decryptor_state, DecryptorState::Error);
        let DecryptorState::Streaming { decryptor, .. } = old_state else {
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
                ChunkDecryptionResult::FinalDecryptedChunk(decrypted_data)
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
    Aes256Gcm(Box<EncryptorBE32<Aes256Gcm>>),
    ChaCha20Poly1305(EncryptorBE32<ChaCha20Poly1305>),
}

impl InnerEncryptor {
    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes256Gcm(enc) => enc.encrypt_next(plaintext).map_err(|_| ()),
            Self::ChaCha20Poly1305(enc) => enc.encrypt_next(plaintext).map_err(|_| ()),
        }
    }

    fn encrypt_last(self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes256Gcm(enc) => enc.encrypt_last(plaintext).map_err(|_| ()),
            Self::ChaCha20Poly1305(enc) => enc.encrypt_last(plaintext).map_err(|_| ()),
        }
    }
}

enum EncryptorState {
    Streaming { encryptor: InnerEncryptor },
    Done,
    Error,
}

/// Streaming chunked-AEAD (STREAM BE32) encryptor. The AEAD primitive (AES-256-GCM or
/// ChaCha20-Poly1305) is inferred from the supplied key's [`SymmetricCryptoKey`] variant, and
/// the 7-byte nonce prefix is generated at construction time. Because the header no longer
/// carries the plaintext length, `HEADER_LEN || HEADER` is emitted as a prefix on the first
/// produced chunk and the remaining chunks stream out incrementally — no buffering of the
/// whole ciphertext.
pub(crate) struct StreamingChunkedAeadEncryptor {
    // Plaintext bytes that have been passed in but not yet encrypted. Bytes are appended on
    // each `update` and drained `DEFAULT_PLAINTEXT_CHUNK_SIZE` at a time via `encrypt_next`. On
    // `last_block = true`, any remaining bytes (0..=DEFAULT_PLAINTEXT_CHUNK_SIZE) are
    // encrypted via `encrypt_last`.
    buffer: Vec<u8>,
    // `HEADER_LEN || HEADER`, prepended to the first emitted chunk and then drained.
    pending_header: Vec<u8>,
    encryptor_state: EncryptorState,
}

impl StreamingChunkedAeadEncryptor {
    pub(crate) fn try_new(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        let stream_key = StreamKey::try_from_symmetric(key)?;

        let nonce_prefix: NoncePrefix = rand::rng().random();
        let nonce: Array<u8, U7> = nonce_prefix.into();
        let encryptor = match stream_key.algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&stream_key.enc_key);
                InnerEncryptor::Aes256Gcm(Box::new(EncryptorBE32::from_aead(cipher, &nonce)))
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&stream_key.enc_key);
                InnerEncryptor::ChaCha20Poly1305(EncryptorBE32::from_aead(cipher, &nonce))
            }
        };

        let header = StreamHeader {
            algorithm: stream_key.algorithm,
            key_id: stream_key.key_id.clone(),
            chunk_size: DEFAULT_PLAINTEXT_CHUNK_SIZE as u64,
            iv: nonce_prefix,
        };
        let header_bytes = header.encode();
        let header_len: u32 = header_bytes
            .len()
            .try_into()
            .expect("CBOR header fits in u32");
        let mut pending_header = Vec::with_capacity(HEADER_LEN_PREFIX_SIZE + header_bytes.len());
        pending_header.extend_from_slice(&header_len.to_be_bytes());
        pending_header.extend_from_slice(&header_bytes);

        Ok(Self {
            buffer: Vec::new(),
            pending_header,
            encryptor_state: EncryptorState::Streaming { encryptor },
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
        // final chunk; the trailing 0..=DEFAULT_PLAINTEXT_CHUNK_SIZE bytes go to `encrypt_last`
        // below.
        let mut out = Vec::new();
        if let EncryptorState::Streaming { encryptor } = &mut self.encryptor_state {
            while self.buffer.len() > DEFAULT_PLAINTEXT_CHUNK_SIZE {
                let pt: Vec<u8> = self.buffer.drain(..DEFAULT_PLAINTEXT_CHUNK_SIZE).collect();
                match encryptor.encrypt_next(pt.as_slice()) {
                    Ok(ct) => out.extend_from_slice(&ct),
                    Err(_) => {
                        self.encryptor_state = EncryptorState::Error;
                        return ChunkEncryptionResult::Error;
                    }
                }
            }
        }

        if !last_block {
            if out.is_empty() {
                return ChunkEncryptionResult::NeedMoreData;
            }
            let mut payload = std::mem::take(&mut self.pending_header);
            payload.extend_from_slice(&out);
            return ChunkEncryptionResult::EncryptedChunk(payload);
        }

        // Final chunk. `encrypt_last` consumes the encryptor; swap the state out and reinsert
        // `Done`/`Error` based on the outcome.
        let old_state = std::mem::replace(&mut self.encryptor_state, EncryptorState::Error);
        let EncryptorState::Streaming { encryptor } = old_state else {
            return ChunkEncryptionResult::Error;
        };
        let final_pt: Vec<u8> = std::mem::take(&mut self.buffer);
        match encryptor.encrypt_last(final_pt.as_slice()) {
            Ok(ct) => {
                let mut payload = std::mem::take(&mut self.pending_header);
                payload.extend_from_slice(&out);
                payload.extend_from_slice(&ct);
                self.encryptor_state = EncryptorState::Done;
                ChunkEncryptionResult::FinalEncryptedChunk(payload)
            }
            Err(_) => {
                self.encryptor_state = EncryptorState::Error;
                ChunkEncryptionResult::Error
            }
        }
    }
}

/// Random-access decryptor for the chunked-AEAD STREAM wire format. Holds the key but no
/// per-stream state; a single instance can serve many independent `decrypt_range` calls
/// against different (or the same) wire stream. The algorithm and IV are read from each
/// wire's CBOR header at call time.
///
/// Each call reconstructs the per-chunk nonce from the wire's nonce prefix plus the chunk
/// index and last-block flag, then decrypts the chunks that overlap the requested plaintext
/// range using the underlying AEAD primitive directly. The STREAM construction authenticates
/// each chunk independently, so reading a subset of chunks is sound: any returned bytes have
/// been authenticated, and chunks outside the range are not read.
pub(crate) struct RandomAccessChunkedAeadDecryptor {
    key: StreamKey,
}

impl RandomAccessChunkedAeadDecryptor {
    pub(crate) fn try_new(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        Ok(Self {
            key: StreamKey::try_from_symmetric(key)?,
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

impl<R> super::RandomAccessDecryptor<R> for RandomAccessChunkedAeadDecryptor
where
    R: RandomAccessDataSource,
{
    type Error = ();

    async fn decrypt_range(
        &self,
        data_source: R,
        total_len: usize,
        range: Range<usize>,
    ) -> Result<Vec<u8>, ()> {
        if range.start > range.end {
            return Err(());
        }

        // Read the 4-byte HEADER_LEN prefix.
        let len_bytes = data_source
            .read_range(0..HEADER_LEN_PREFIX_SIZE)
            .await
            .map_err(|_| ())?;
        let len_bytes: [u8; HEADER_LEN_PREFIX_SIZE] =
            len_bytes.as_slice().try_into().map_err(|_| ())?;
        let header_len = u32::from_be_bytes(len_bytes) as usize;

        // Read the CBOR header.
        let header_bytes = data_source
            .read_range(HEADER_LEN_PREFIX_SIZE..HEADER_LEN_PREFIX_SIZE + header_len)
            .await
            .map_err(|_| ())?;
        let header = StreamHeader::decode(&header_bytes)?;

        // The wire header must agree with the supplied key on both the AEAD primitive and the
        // key id; otherwise we'd be decrypting with the wrong key/algorithm.
        if header.algorithm != self.key.algorithm
            || !bool::from(header.key_id.ct_eq(&self.key.key_id))
        {
            return Err(());
        }

        // The ciphertext region is everything after the header; its length determines the
        // chunk layout (the plaintext length is no longer stored in the header).
        let header_region_len = HEADER_LEN_PREFIX_SIZE.checked_add(header_len).ok_or(())?;
        let ciphertext_region_len = total_len.checked_sub(header_region_len).ok_or(())?;
        let layout = StreamLayout::from_wire(&header, ciphertext_region_len)?;

        if range.end > layout.plaintext_length {
            return Err(());
        }
        if range.start == range.end {
            return Ok(Vec::new());
        }

        let start_chunk = range.start / layout.plaintext_chunk_size;
        let end_chunk = (range.end - 1) / layout.plaintext_chunk_size;
        let last_chunk_idx = layout.num_chunks - 1;
        let ct_region_start = HEADER_LEN_PREFIX_SIZE + header_len;

        // Decrypt each overlapping chunk and concatenate, then slice down to the exact
        // plaintext range.
        let mut decrypted =
            Vec::with_capacity((end_chunk - start_chunk + 1) * layout.plaintext_chunk_size);
        // Construct the AEAD cipher once to keep the (relatively expensive) key schedule out
        // of the per-chunk loop.
        match header.algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&self.key.enc_key);
                for chunk_idx in start_chunk..=end_chunk {
                    let is_last = chunk_idx == last_chunk_idx;
                    let ct_offset = ct_region_start + chunk_idx * layout.ciphertext_chunk_size;
                    let ct_len = if is_last {
                        layout.last_chunk_ct_len
                    } else {
                        layout.ciphertext_chunk_size
                    };
                    let ct = data_source
                        .read_range(ct_offset..ct_offset + ct_len)
                        .await
                        .map_err(|_| ())?;
                    let nonce = chunk_nonce(&header.iv, chunk_idx as u32, is_last);
                    let pt = cipher.decrypt(&nonce, ct.as_slice()).map_err(|_| ())?;
                    decrypted.extend_from_slice(&pt);
                }
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&self.key.enc_key);
                for chunk_idx in start_chunk..=end_chunk {
                    let is_last = chunk_idx == last_chunk_idx;
                    let ct_offset = ct_region_start + chunk_idx * layout.ciphertext_chunk_size;
                    let ct_len = if is_last {
                        layout.last_chunk_ct_len
                    } else {
                        layout.ciphertext_chunk_size
                    };
                    let ct = data_source
                        .read_range(ct_offset..ct_offset + ct_len)
                        .await
                        .map_err(|_| ())?;
                    let nonce = chunk_nonce(&header.iv, chunk_idx as u32, is_last);
                    let pt = cipher.decrypt(&nonce, ct.as_slice()).map_err(|_| ())?;
                    decrypted.extend_from_slice(&pt);
                }
            }
        }

        let local_start = range.start - start_chunk * layout.plaintext_chunk_size;
        let local_end = local_start + (range.end - range.start);
        Ok(decrypted[local_start..local_end].to_vec())
    }
}

/// Benchmark-only bridge exposing the chunked-AEAD STREAM ciphers to the external `benches/`
/// crate, which can only see the public API. Gated behind `test-utils` so it never reaches a
/// production build. Not part of the stable public surface.
#[cfg(feature = "test-utils")]
pub mod bench_support {
    use std::ops::Range;

    use super::{
        RandomAccessChunkedAeadDecryptor, StreamingChunkedAeadDecryptor,
        StreamingChunkedAeadEncryptor,
    };
    use crate::{
        SymmetricCryptoKey,
        stream::{
            ChunkDecryptionResult, ChunkEncryptionResult, RandomAccessDataSource,
            RandomAccessDecryptor, StreamingDecryptor, StreamingEncryptor,
        },
    };

    /// Public selector for the AEAD primitive. The algorithm is now carried by the key variant,
    /// so this is only used by benches to build a key of the right type.
    #[derive(Clone, Copy)]
    pub enum BenchAeadAlgorithm {
        /// AES-256-GCM.
        Aes256Gcm,
        /// ChaCha20-Poly1305.
        ChaCha20Poly1305,
    }

    impl BenchAeadAlgorithm {
        /// Build a fresh random key of the variant matching this algorithm.
        pub fn make_key(self) -> SymmetricCryptoKey {
            match self {
                BenchAeadAlgorithm::Aes256Gcm => SymmetricCryptoKey::make(crate::SymmetricKeyAlgorithm::Aes256Gcm),
                BenchAeadAlgorithm::ChaCha20Poly1305 => {
                    SymmetricCryptoKey::make(crate::SymmetricKeyAlgorithm::ChaCha20Poly1305)
                }
            }
        }
    }

    /// Drive the streaming encryptor over `plaintext` in `input_chunk`-sized writes, returning
    /// the full wire stream.
    pub fn encrypt(key: &SymmetricCryptoKey, plaintext: &[u8], input_chunk: usize) -> Vec<u8> {
        let mut enc = StreamingChunkedAeadEncryptor::try_new(key)
            .ok()
            .expect("encryptor construction");
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + input_chunk).min(plaintext.len());
            let chunk = &plaintext[offset..end];
            offset = end;
            let last = offset == plaintext.len();
            match enc.update(chunk, last) {
                ChunkEncryptionResult::NeedMoreData => {}
                ChunkEncryptionResult::EncryptedChunk(bytes) => out.extend_from_slice(&bytes),
                ChunkEncryptionResult::FinalEncryptedChunk(bytes) => {
                    out.extend_from_slice(&bytes);
                    break;
                }
                ChunkEncryptionResult::Error => panic!("encryption error"),
            }
        }
        out
    }

    /// Drive the streaming decryptor over `wire` in `input_chunk`-sized writes, returning the
    /// recovered plaintext.
    pub fn decrypt(key: &SymmetricCryptoKey, wire: &[u8], input_chunk: usize) -> Vec<u8> {
        let mut dec = StreamingChunkedAeadDecryptor::try_new(key)
            .ok()
            .expect("decryptor construction");
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + input_chunk).min(wire.len());
            let chunk = &wire[offset..end];
            offset = end;
            let last = offset == wire.len();
            match dec.update(chunk, last) {
                ChunkDecryptionResult::NeedMoreData => {}
                ChunkDecryptionResult::DecryptedChunk(bytes) => out.extend_from_slice(&bytes),
                ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                    out.extend_from_slice(&bytes);
                    break;
                }
                ChunkDecryptionResult::Error => panic!("decryption error"),
            }
        }
        out
    }

    struct InMemorySource<'a>(&'a [u8]);

    impl RandomAccessDataSource for InMemorySource<'_> {
        type Error = ();

        async fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>, Self::Error> {
            if range.end > self.0.len() {
                return Err(());
            }
            Ok(self.0[range].to_vec())
        }
    }

    /// Random-access decrypt of `range` from an in-memory `wire` stream.
    pub async fn decrypt_range(
        key: &SymmetricCryptoKey,
        wire: &[u8],
        range: Range<usize>,
    ) -> Vec<u8> {
        let dec = RandomAccessChunkedAeadDecryptor::try_new(key)
            .ok()
            .expect("random access decryptor construction");
        let total_len = wire.len();
        dec.decrypt_range(InMemorySource(wire), total_len, range)
            .await
            .expect("decrypt_range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SymmetricCryptoKey,
        stream::{
            ChunkDecryptionResult, ChunkEncryptionResult, RandomAccessDataSource,
            RandomAccessDecryptor, StreamingDecryptor, StreamingEncryptor,
        },
    };

    fn test_key(algorithm: AeadAlgorithm) -> SymmetricCryptoKey {
        match algorithm {
            AeadAlgorithm::Aes256Gcm => SymmetricCryptoKey::make(crate::SymmetricKeyAlgorithm::Aes256Gcm),
            AeadAlgorithm::ChaCha20Poly1305 => SymmetricCryptoKey::make(crate::SymmetricKeyAlgorithm::ChaCha20Poly1305),
        }
    }

    fn encrypt_all(key: &SymmetricCryptoKey, plaintext: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut enc = StreamingChunkedAeadEncryptor::try_new(key)
            .ok()
            .expect("encryptor construction");
        let mut pt = plaintext.to_vec();
        let mut out = Vec::new();
        loop {
            let take = chunk_size.min(pt.len());
            let chunk: Vec<u8> = pt.drain(..take).collect();
            let last = pt.is_empty();
            match enc.update(&chunk, last) {
                ChunkEncryptionResult::NeedMoreData => {}
                ChunkEncryptionResult::EncryptedChunk(bytes) => out.extend_from_slice(&bytes),
                ChunkEncryptionResult::FinalEncryptedChunk(bytes) => {
                    out.extend_from_slice(&bytes);
                    break;
                }
                ChunkEncryptionResult::Error => panic!("encryption error"),
            }
        }
        out
    }

    fn decrypt_all(key: &SymmetricCryptoKey, wire: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut dec = StreamingChunkedAeadDecryptor::try_new(key)
            .ok()
            .expect("decryptor construction");
        let mut ct = wire.to_vec();
        let mut out = Vec::new();
        loop {
            let take = chunk_size.min(ct.len());
            let chunk: Vec<u8> = ct.drain(..take).collect();
            let last = ct.is_empty();
            match dec.update(&chunk, last) {
                ChunkDecryptionResult::NeedMoreData => {}
                ChunkDecryptionResult::DecryptedChunk(bytes) => out.extend_from_slice(&bytes),
                ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                    out.extend_from_slice(&bytes);
                    break;
                }
                ChunkDecryptionResult::Error => panic!("decryption error"),
            }
        }
        out
    }

    fn try_decrypt_all(key: &SymmetricCryptoKey, wire: &[u8]) -> Result<Vec<u8>, ()> {
        let mut dec = StreamingChunkedAeadDecryptor::try_new(key)
            .ok()
            .expect("decryptor construction");
        match dec.update(wire, true) {
            ChunkDecryptionResult::FinalDecryptedChunk(bytes) => Ok(bytes),
            _ => Err(()),
        }
    }

    #[test]
    fn roundtrip_aes_gcm_short() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext = b"hello aead stream roundtrip test plaintext.";
        let wire = encrypt_all(&key, plaintext, 13);
        let out = decrypt_all(&key, &wire, 9);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn roundtrip_chacha20poly1305_short() {
        let key = test_key(AeadAlgorithm::ChaCha20Poly1305);
        let plaintext = b"hello aead stream roundtrip test plaintext.";
        let wire = encrypt_all(&key, plaintext, 13);
        let out = decrypt_all(&key, &wire, 9);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        for alg in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
            let key = test_key(alg);
            let wire = encrypt_all(&key, &[], 16);
            let out = decrypt_all(&key, &wire, 16);
            assert!(out.is_empty());
        }
    }

    #[test]
    fn roundtrip_multi_chunk() {
        // Cross a chunk boundary: 64 KiB + something.
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext: Vec<u8> = (0..(DEFAULT_PLAINTEXT_CHUNK_SIZE + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let wire = encrypt_all(&key, &plaintext, 8192);
        let out = decrypt_all(&key, &wire, 8192);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn modified_wire_fails() {
        let key = test_key(AeadAlgorithm::ChaCha20Poly1305);
        let plaintext = b"some plaintext to be tampered with later";
        let mut wire = encrypt_all(&key, plaintext, 64);
        // Flip a bit somewhere in the ciphertext region (past the small CBOR header).
        let idx = wire.len() - 5;
        wire[idx] ^= 0x01;
        assert!(try_decrypt_all(&key, &wire).is_err());
    }

    #[test]
    fn truncated_wire_fails() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext = b"some plaintext that will be truncated";
        let wire = encrypt_all(&key, plaintext, 64);
        let truncated = &wire[..wire.len() - 3];
        assert!(try_decrypt_all(&key, truncated).is_err());
    }

    #[test]
    fn missing_header_fails() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        // Only 2 bytes — not even the HEADER_LEN prefix.
        assert!(try_decrypt_all(&key, &[0u8, 0u8]).is_err());
    }

    #[test]
    fn inspect_stream_header_reports_metadata() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let wire = encrypt_all(&key, b"inspect me", 64);
        // The first 500 bytes are more than enough to contain the small CBOR header.
        let prefix = &wire[..wire.len().min(500)];
        let header = inspect_stream_header(prefix).expect("header parses");
        assert_eq!(header.algorithm, AeadAlgorithm::Aes256Gcm);
        assert_eq!(header.chunk_size, DEFAULT_PLAINTEXT_CHUNK_SIZE as u64);
        assert_eq!(header.key_id.as_slice(), key.key_id().unwrap().as_slice());
        // Debug formatting should not panic and should mention the algorithm.
        let debug = format!("{header:?}");
        assert!(debug.contains("aes-gcm"));
    }

    #[test]
    #[ignore = "Manual test to print the chunked AEAD stream header"]
    fn print_stream_header() {
        for alg in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
            let key = test_key(alg);
            let wire = encrypt_all(&key, b"header inspection sample", 64);
            let prefix = &wire[..wire.len().min(500)];
            let header = inspect_stream_header(prefix).expect("header parses");
            println!("{header:#?}");
        }
    }

    #[test]
    fn wrong_key_id_is_rejected() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext = b"encrypted under one key, decrypted under another";
        let wire = encrypt_all(&key, plaintext, 64);
        // A different key of the same algorithm has a different key id.
        let other_key = test_key(AeadAlgorithm::Aes256Gcm);
        assert!(try_decrypt_all(&other_key, &wire).is_err());
    }

    #[test]
    fn wrong_algorithm_is_rejected() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext = b"encrypted with aes, attempted decrypt with chacha";
        let wire = encrypt_all(&key, plaintext, 64);
        let chacha_key = test_key(AeadAlgorithm::ChaCha20Poly1305);
        assert!(try_decrypt_all(&chacha_key, &wire).is_err());
    }

    struct InMemorySource(Vec<u8>);

    impl RandomAccessDataSource for InMemorySource {
        type Error = ();

        async fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>, Self::Error> {
            if range.end > self.0.len() {
                return Err(());
            }
            Ok(self.0[range].to_vec())
        }
    }

    async fn assert_range_roundtrip(
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        range: Range<usize>,
    ) {
        let key = test_key(algorithm);
        let wire = encrypt_all(&key, plaintext, 8192);
        let total_len = wire.len();
        let dec = RandomAccessChunkedAeadDecryptor::try_new(&key)
            .ok()
            .expect("random access decryptor construction");
        let source = InMemorySource(wire);
        let got = dec
            .decrypt_range(source, total_len, range.clone())
            .await
            .expect("decrypt_range");
        assert_eq!(got, plaintext[range]);
    }

    #[tokio::test]
    async fn random_access_within_first_chunk() {
        let plaintext: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
        assert_range_roundtrip(AeadAlgorithm::Aes256Gcm, &plaintext, 10..1500).await;
    }

    #[tokio::test]
    async fn random_access_across_chunks() {
        let plaintext: Vec<u8> = (0..(DEFAULT_PLAINTEXT_CHUNK_SIZE * 2 + 500))
            .map(|i| (i % 251) as u8)
            .collect();
        let end = DEFAULT_PLAINTEXT_CHUNK_SIZE + 100;
        assert_range_roundtrip(
            AeadAlgorithm::ChaCha20Poly1305,
            &plaintext,
            (DEFAULT_PLAINTEXT_CHUNK_SIZE - 50)..end,
        )
        .await;
    }

    #[tokio::test]
    async fn random_access_full_range() {
        let plaintext: Vec<u8> = (0..(DEFAULT_PLAINTEXT_CHUNK_SIZE + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        assert_range_roundtrip(AeadAlgorithm::Aes256Gcm, &plaintext, 0..plaintext.len()).await;
    }

    #[tokio::test]
    async fn random_access_empty_range() {
        let plaintext = b"abcdef";
        assert_range_roundtrip(AeadAlgorithm::ChaCha20Poly1305, plaintext, 3..3).await;
    }

    #[tokio::test]
    async fn random_access_out_of_bounds_fails() {
        let key = test_key(AeadAlgorithm::Aes256Gcm);
        let plaintext = b"abcdef";
        let wire = encrypt_all(&key, plaintext, 64);
        let total_len = wire.len();
        let dec = RandomAccessChunkedAeadDecryptor::try_new(&key)
            .ok()
            .expect("random access decryptor construction");
        let source = InMemorySource(wire);
        assert!(dec.decrypt_range(source, total_len, 0..1000).await.is_err());
    }
}
