//! # AES-256-CBC-HMAC-Legacy-Stream
//!
//! Aes256CBC-HMAC-Legacy-Stream is a format for streaming encryption of attachments. It consists of
//! a header, an AES-CBC stream, and a hmac over IV + CBC ciphertext. Because there is just one HMAC
//! over the entire stream, it is not permissible to decrypt a partial portion of this stream, as
//! the integrity of that portion cannot be guaranteed.
//!
//! ## Format
//! The stream looks as follows:
//! ```text
//! (KEY_E, KEY_A) = KEY
//! IV | HMAC[KEY_A] (over IV + ciphertext) | AES-CBC[KEY_E]() ciphertext
//! ```
//!
//! ## Limitations
//!
//! Because the HMAC is written to the start, encryption must be buffered in memory fully
//! before emitting out as an encryption stream, since the HMAC can only be calculated
//! after all ciphertext is produced. This is a limitation to the format.
//!
//! Further, the HMAC covers the entire stream, not chunks of it, so the entire stream
//! must be fully read before the output is used. IMPORTANT: YOU MUST READ THE ENTIRE STREAM
//! BEFORE USING THE DECRYPTED OUTPUT. This contract cannot be enforced by the interface and
//! requires the correct usage of the caller.
//!
//! NOTE: The attachments, stored on the server contain a header idicating which format they are
//! encrypted with. This header is *NOT* included in the stream processed by this file, and is
//! expected to be stripped by the caller before passing the ciphertext to this code.
//!
//! Random access is not possible with this format, both because of the use of CBC chaining,
//! and because of the single HMAC over the entire cipher stream.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::HmacImpl;
use hybrid_array::Array;
use rand::Rng;
use subtle::ConstantTimeEq;

use super::{
    ChunkDecryptionResult, ChunkEncryptionResult, StreamCreationError, StreamingDecryptor,
    StreamingEncryptor,
};
use crate::{
    Aes256CbcHmacKey, SymmetricCryptoKey, stream::large_memory_buffer::Buffer,
    util::PbkdfSha256Hmac,
};

const AES256_CBC_BLOCK_SIZE: usize = 16;
const AES256_CBC_IV_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
const HEADER_LENGTH: usize = AES256_CBC_IV_SIZE + HMAC_SIZE;
const EMISSION_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// CBC IV
type Iv = [u8; AES256_CBC_IV_SIZE];
/// HMAC over IV + Ciphertext
type Mac = [u8; HMAC_SIZE];
/// Header is IV || HMAC
type StreamHeaderBytes = [u8; HEADER_LENGTH];
type CbcCiphertextBlock = [u8; AES256_CBC_BLOCK_SIZE];

struct CbcDecryptor {
    decryptor: cbc::Decryptor<aes::Aes256>,
}

impl CbcDecryptor {
    fn new(key: &[u8; 32], iv: &Iv) -> Self {
        Self {
            decryptor: cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into()),
        }
    }

    fn decrypt_block(&mut self, block: &CbcCiphertextBlock) -> CbcPlaintextBlock {
        let mut block: Array<u8, _> = (*block).into();
        self.decryptor.decrypt_block(&mut block);
        CbcPlaintextBlock(
            block
                .as_slice()
                .try_into()
                .expect("block size checked by type"),
        )
    }
}

struct CbcEncryptor {
    encryptor: cbc::Encryptor<aes::Aes256>,
}

impl CbcEncryptor {
    fn new(key: &[u8; 32], iv: &Iv) -> Self {
        Self {
            encryptor: cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into()),
        }
    }

    fn encrypt_block(&mut self, block: &mut CbcPlaintextBlock) -> CbcCiphertextBlock {
        let mut block_array: Array<u8, _> = block.0.into();
        self.encryptor.encrypt_block(&mut block_array);
        block_array
            .as_slice()
            .try_into()
            .expect("block size checked by type")
    }
}

/// A higher level interface over the HMAC validation of the attachment ciphertext
struct HmacStreamValidator {
    hmac: PbkdfSha256Hmac,
}

impl HmacStreamValidator {
    fn new(mac_key: &[u8; 32], iv: &Iv) -> Self {
        let mut hmac = PbkdfSha256Hmac::new_from_slice(mac_key);
        hmac.update(iv);
        Self { hmac }
    }

    /// Called on each CBC ciphertext block in order
    fn read_block(&mut self, data: &CbcCiphertextBlock) {
        self.hmac.update(data);
    }

    /// Called after the final block has been ingested by `read_block`, during encryption.
    fn end_stream(&self) -> Mac {
        // `HmacImpl::finalize` consumes self; clone so the validator can stay borrowed by the
        // decryptor state machine and be dropped normally when the state transitions.
        let mac: Mac = self
            .hmac
            .clone()
            .finalize()
            .as_slice()
            .try_into()
            .expect("hmac output is 32 bytes");
        mac
    }

    /// Called after the final block has been ingested by `read_block`, during decryption. Returns
    /// whether the calculated HMAC matches the expected HMAC from the header.
    fn validate_stream_end(&self, expected_mac: &Mac) -> bool {
        // `HmacImpl::finalize` consumes self; clone so the validator can stay borrowed
        // by the decryptor state machine and be dropped normally when the state transitions.
        let calculated_mac = self.hmac.clone().finalize();
        calculated_mac.as_slice().ct_eq(expected_mac).into()
    }
}

#[derive(Clone)]
struct StreamHeader {
    iv: Iv,
    mac: Mac,
}

impl From<&StreamHeader> for StreamHeaderBytes {
    fn from(header: &StreamHeader) -> Self {
        let mut out = [0u8; HEADER_LENGTH];
        out[..AES256_CBC_IV_SIZE].copy_from_slice(&header.iv);
        out[AES256_CBC_IV_SIZE..].copy_from_slice(&header.mac);
        out
    }
}

impl From<&StreamHeaderBytes> for StreamHeader {
    fn from(bytes: &StreamHeaderBytes) -> Self {
        let iv: Iv = bytes[..AES256_CBC_IV_SIZE]
            .try_into()
            .expect("slice length checked by type");
        let mac: Mac = bytes[AES256_CBC_IV_SIZE..]
            .try_into()
            .expect("slice length checked by type");
        StreamHeader { iv, mac }
    }
}

enum Pkcs7ValidationResult {
    // The padding is valid and the containing plaintext is the contained plaintext data in the
    // last chunk
    Valid(Vec<u8>),
    Invalid,
}

struct CbcPlaintextBlock([u8; AES256_CBC_BLOCK_SIZE]);

impl AsRef<[u8]> for CbcPlaintextBlock {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CbcPlaintextBlock {
    /// In PKCS7, the last N bytes of plaintext MUST all have the value N.
    /// This function validates the padding for the last block and returns the contained plaintext
    fn is_valid_pkcs7_padding(&self) -> Pkcs7ValidationResult {
        let data = &self.0;
        if data.is_empty() {
            return Pkcs7ValidationResult::Invalid;
        }
        let padding_len = *data.last().expect("data is a fixed-size non-empty array") as usize;
        if padding_len == 0 || padding_len > AES256_CBC_BLOCK_SIZE {
            return Pkcs7ValidationResult::Invalid;
        }
        if data[data.len() - padding_len..]
            .iter()
            .all(|&b| b as usize == padding_len)
        {
            Pkcs7ValidationResult::Valid(data[..data.len() - padding_len].to_vec())
        } else {
            Pkcs7ValidationResult::Invalid
        }
    }
}

enum DecryptorState {
    Uninitialized {
        key: Aes256CbcHmacKey,
    },
    Streaming {
        decryptor: Box<CbcDecryptor>,
        integrity_validator: HmacStreamValidator,
        expected_mac: Mac,
    },
    Done,
    Error,
}

enum DecryptorInitializeWithHeaderError {
    AlreadyInitialized,
}

impl DecryptorState {
    /// Initializes the decryptor with the stream header. This
    /// changes the state from `Uninitialized` to `Streaming`, and must be called before any
    /// decryption can occur.
    fn initialize(
        &mut self,
        header: StreamHeader,
    ) -> Result<(), DecryptorInitializeWithHeaderError> {
        match self {
            Self::Uninitialized { key } => {
                *self = Self::Streaming {
                    decryptor: Box::new(CbcDecryptor::new(&key.enc_key.0, &header.iv)),
                    integrity_validator: HmacStreamValidator::new(&key.mac_key.0, &header.iv),
                    expected_mac: header.mac,
                };
                Ok(())
            }
            _ => Err(DecryptorInitializeWithHeaderError::AlreadyInitialized),
        }
    }
}

/// Reads and removes the first block from the buffer. The size must
/// be checked by the caller before calling this function, and it may panic otherwise.
fn read_block_ciphertext(buffer: &mut Vec<u8>) -> CbcCiphertextBlock {
    buffer
        .drain(..AES256_CBC_BLOCK_SIZE)
        .as_slice()
        .try_into()
        .expect("slice length checked by external condition")
}

/// Reads and removes the first block from the buffer. The size must
/// be checked by the caller before calling this function, and it may panic otherwise.
fn read_plaintext_block(buffer: &mut Vec<u8>) -> Option<CbcPlaintextBlock> {
    if buffer.len() < AES256_CBC_BLOCK_SIZE {
        return None;
    }
    Some(CbcPlaintextBlock(
        buffer
            .drain(..AES256_CBC_BLOCK_SIZE)
            .as_slice()
            .try_into()
            .expect("slice length checked by condition"),
    ))
}

fn read_header(buffer: &mut Vec<u8>) -> Option<StreamHeader> {
    if buffer.len() >= HEADER_LENGTH {
        let header_bytes: StreamHeaderBytes = buffer
            .drain(..HEADER_LENGTH)
            .as_slice()
            .try_into()
            .expect("slice length checked by condition");
        Some((&header_bytes).into())
    } else {
        None
    }
}

/// Streaming AES-256-CBC + HMAC-SHA256 decryptor. The HMAC is verified only when
/// [`StreamingDecryptor::update`] is called with `last_block = true`; bytes returned from
/// earlier `update` calls as [`ChunkDecryptionResult::DecryptedChunk`] are decrypted but **not
/// yet authenticated** and must be treated as untrusted until the terminal
/// [`ChunkDecryptionResult::FinalDecryptedChunk`] is observed.
pub struct StreamingAes256CbcHmacDecryptor {
    // Bytes that have been passed in but not yet processed by the crypto implementation.
    // When passing in external data, they are first concatenated to the buffer, then the
    // crypto implementation reads bytes
    buffer: Vec<u8>,
    decryptor_state: DecryptorState,
}

impl StreamingAes256CbcHmacDecryptor {
    pub(crate) fn try_new(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        let key = match key {
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => key,
            _ => return Err(StreamCreationError::WrongKeyType),
        };
        Ok(Self {
            buffer: Vec::new(),
            decryptor_state: DecryptorState::Uninitialized { key: key.clone() },
        })
    }
}

impl StreamingDecryptor for StreamingAes256CbcHmacDecryptor {
    /// Updates the decryptor with a chunk of ciphertext. If `last_block` is false, the chunk must
    /// not contain the end of the stream, if it is true, it must contain the end of the stream.
    fn update(&mut self, ciphertext_chunk: &[u8], last_block: bool) -> ChunkDecryptionResult {
        self.buffer.extend_from_slice(ciphertext_chunk);

        // If the decryptor is in an error or done state, we should not proceed with decryption and
        // just return an error.
        if matches!(
            self.decryptor_state,
            DecryptorState::Error | DecryptorState::Done
        ) {
            return ChunkDecryptionResult::Error;
        }

        // If the decryptor is uninitialized, it must be initialized before proceeding. The
        // header bytes live at the start of the wire stream, so they are accumulated in
        // `self.buffer` and drained from there once enough bytes have arrived.
        if matches!(self.decryptor_state, DecryptorState::Uninitialized { .. }) {
            if self.buffer.len() < HEADER_LENGTH {
                if last_block {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }
                return ChunkDecryptionResult::NeedMoreData;
            }
            let header: StreamHeader =
                read_header(&mut self.buffer).expect("header length checked by condition above");
            if self.decryptor_state.initialize(header).is_err() {
                self.decryptor_state = DecryptorState::Error;
                return ChunkDecryptionResult::Error;
            }
        }

        // The decryptor can now only be Streaming
        if let DecryptorState::Streaming {
            decryptor,
            integrity_validator,
            expected_mac,
        } = &mut self.decryptor_state
        {
            // Process as many blocks as possible. On non-last calls, hold back one full block
            // so PKCS7 stripping can run against it at finalize. (The decryptor must not emit
            // padding bytes to the caller — but it doesn't know which block is the last until
            // `last_block = true`.)
            let blocks_to_process = if last_block {
                self.buffer.len() / AES256_CBC_BLOCK_SIZE
            } else {
                self.buffer.len().saturating_sub(1) / AES256_CBC_BLOCK_SIZE
            };

            let mut decrypted_data = Vec::new();
            for _ in 0..blocks_to_process {
                let ciphertext_block: CbcCiphertextBlock = read_block_ciphertext(&mut self.buffer);
                integrity_validator.read_block(&ciphertext_block);
                let plaintext_block = decryptor.decrypt_block(&ciphertext_block);
                decrypted_data.extend_from_slice(plaintext_block.as_ref());
            }

            if last_block {
                // Finalize the HMAC validation. If it fails, we should discard all decrypted data
                // and return an error.
                if !integrity_validator.validate_stream_end(expected_mac) {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }

                // Strip and validate PKCS7 padding from the trailing decrypted block.
                if decrypted_data.len() < AES256_CBC_BLOCK_SIZE {
                    self.decryptor_state = DecryptorState::Error;
                    return ChunkDecryptionResult::Error;
                }

                // The end of the stream is guaranteed to be a PKCS7 padding block. This padding
                // must be validated and stripped.
                let tail_start = decrypted_data.len() - AES256_CBC_BLOCK_SIZE;
                let last_block: CbcPlaintextBlock = CbcPlaintextBlock(
                    decrypted_data
                        .drain(tail_start..)
                        .as_slice()
                        .try_into()
                        .expect("drained one block"),
                );
                match last_block.is_valid_pkcs7_padding() {
                    Pkcs7ValidationResult::Valid(plaintext) => {
                        decrypted_data.extend_from_slice(&plaintext);
                    }
                    Pkcs7ValidationResult::Invalid => {
                        self.decryptor_state = DecryptorState::Error;
                        return ChunkDecryptionResult::Error;
                    }
                }

                self.decryptor_state = DecryptorState::Done;
                return ChunkDecryptionResult::FinalDecryptedChunk(decrypted_data);
            } else {
                return ChunkDecryptionResult::DecryptedChunk(decrypted_data);
            }
        }

        // This should be unreachable
        ChunkDecryptionResult::Error
    }
}

struct CiphertextBuffer {
    // Backing store for ciphertext bytes that have been encrypted but not yet emitted. On WASM,
    // this is a JS Uint8Array to avoid copying between Rust and JS memory; on native, this is a
    // Vec<u8>.
    inner: Buffer,
    // The current size of the buffer. This may be larger than the length of the ciphertext
    // currently stored in the buffer, since the buffer grows in blocks.
    size: usize,
    emitted_bytes: usize,
}

impl CiphertextBuffer {
    fn new() -> Self {
        Self {
            inner: Buffer::new(),
            size: 0,
            emitted_bytes: 0,
        }
    }

    fn append(&mut self, data: &CbcCiphertextBlock) {
        self.inner
            .append(data)
            .expect("buffer should grow to fit");
        self.size += data.len();
    }

    fn emit_chunk(&mut self) -> Option<Vec<u8>> {
        let remaining_bytes = self.size - self.emitted_bytes;
        if remaining_bytes == 0 {
            return None;
        }

        let chunk_size = remaining_bytes.min(EMISSION_CHUNK_SIZE);
        let chunk = self
            .inner
            .index(self.emitted_bytes..self.emitted_bytes + chunk_size)
            .expect("chunk size is always within bounds of the buffer");
        self.emitted_bytes += chunk_size;
        Some(chunk)
    }
}

enum EncryptorState {
    Streaming {
        encryptor: Box<CbcEncryptor>,
        integrity_validator: HmacStreamValidator,
        iv: Iv,
    },
    Emitting,
    Done,
    Error,
}

/// Streaming AES-256-CBC + HMAC-SHA256 encryptor. The IV is generated at construction time
/// and the HMAC is computed over IV || ciphertext, matching the wire format consumed by
/// [`StreamingAes256CbcHmacDecryptor`]. Because the MAC depends on the entire ciphertext,
/// the complete wire stream (`IV, ciphertext`) is only emitted once `update` is
/// called with `last_block = true`, as a single [`ChunkEncryptionResult::FinalEncryptedChunk`].
pub struct StreamingAes256CbcHmacEncryptor {
    // Ciphertext bytes that have been encrypted but not yet emitted. The backing store is a
    // pre-allocated large buffer (released-by-drop on WASM).
    ciphertext_buffer: CiphertextBuffer,
    plaintext_buffer: Vec<u8>,
    encryptor_state: EncryptorState,
}

impl StreamingAes256CbcHmacEncryptor {
    /// Creates a new encryptor with a fresh random IV.
    pub(crate) fn try_new(key: &SymmetricCryptoKey) -> Result<Self, StreamCreationError> {
        let key = match key {
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => key,
            _ => return Err(StreamCreationError::WrongKeyType),
        };

        let mut iv: Iv = [0u8; AES256_CBC_IV_SIZE];
        rand::rng().fill_bytes(&mut iv);

        Ok(Self {
            ciphertext_buffer: CiphertextBuffer::new(),
            plaintext_buffer: Vec::new(),
            encryptor_state: EncryptorState::Streaming {
                encryptor: Box::new(CbcEncryptor::new(&key.enc_key.0, &iv)),
                integrity_validator: HmacStreamValidator::new(&key.mac_key.0, &iv),
                iv,
            },
        })
    }
}

impl StreamingEncryptor for StreamingAes256CbcHmacEncryptor {
    fn update(&mut self, plaintext_chunk: &[u8], last_block: bool) -> ChunkEncryptionResult {
        let (encryptor, stream_validator, iv): (
            &mut Box<CbcEncryptor>,
            &mut HmacStreamValidator,
            &Iv,
        ) = match &mut self.encryptor_state {
            EncryptorState::Error | EncryptorState::Done => {
                return ChunkEncryptionResult::Error;
            }
            EncryptorState::Emitting => {
                if let Some(chunk) = self.ciphertext_buffer.emit_chunk() {
                    return ChunkEncryptionResult::EncryptedChunk(chunk);
                } else {
                    self.encryptor_state = EncryptorState::Done;
                    return ChunkEncryptionResult::FinalEncryptedChunk(Vec::new());
                }
            }
            EncryptorState::Streaming {
                encryptor,
                integrity_validator,
                iv,
            } => (encryptor, integrity_validator, iv),
        };

        self.plaintext_buffer.extend_from_slice(plaintext_chunk);

        // Encrypt all full blocks currently in the buffer plaintext buffer.
        while let Some(mut block) = read_plaintext_block(&mut self.plaintext_buffer) {
            let cipher_block = encryptor.encrypt_block(&mut block);
            stream_validator.read_block(&cipher_block);
            self.ciphertext_buffer.append(&cipher_block);
        }

        if !last_block {
            return ChunkEncryptionResult::NeedMoreData;
        }

        // PKCS7: pad to the next block boundary. If the buffer is already block-aligned (or
        // empty), this appends a full padding block of value BLOCK_SIZE.
        let padding_len = AES256_CBC_BLOCK_SIZE - self.plaintext_buffer.len();
        let mut padding = vec![padding_len as u8; padding_len];
        self.plaintext_buffer.append(&mut padding);

        let Some(mut block) = read_plaintext_block(&mut self.plaintext_buffer) else {
            // This should be unreachable, since the padding guarantees exactly one block should be
            // available.
            self.encryptor_state = EncryptorState::Error;
            return ChunkEncryptionResult::Error;
        };

        let cipher_block = encryptor.encrypt_block(&mut block);
        self.ciphertext_buffer.append(&cipher_block);

        stream_validator.read_block(&cipher_block);
        let mac = stream_validator.end_stream();

        let header: StreamHeaderBytes = (&StreamHeader { iv: *iv, mac }).into();
        self.encryptor_state = EncryptorState::Emitting;
        ChunkEncryptionResult::EncryptedChunk(header.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC_KEY: [u8; 32] = [0u8; 32];
    const MAC_KEY: [u8; 32] = [1u8; 32];
    const PLAINTEXT: &[u8] = b"This is a test vector text for streaming encryption. It is long enough to require multiple CBC blocks.";
    const STREAM_TEST_VECTOR: &[u8] = &[
        202, 35, 233, 113, 188, 138, 45, 92, 122, 28, 38, 85, 31, 242, 192, 113, 213, 46, 222, 105,
        210, 189, 251, 90, 162, 190, 27, 47, 139, 54, 146, 233, 233, 246, 27, 201, 172, 13, 180,
        105, 69, 177, 113, 72, 154, 138, 43, 75, 53, 193, 235, 62, 28, 217, 137, 81, 167, 40, 33,
        95, 241, 1, 154, 92, 69, 252, 151, 218, 106, 46, 189, 208, 154, 123, 192, 207, 253, 155,
        22, 17, 158, 142, 88, 91, 177, 117, 227, 45, 58, 16, 150, 180, 193, 32, 144, 95, 227, 233,
        60, 7, 98, 197, 200, 144, 179, 213, 220, 95, 242, 17, 112, 115, 211, 97, 90, 250, 210, 141,
        200, 157, 156, 71, 133, 165, 246, 161, 110, 127, 232, 225, 121, 190, 235, 121, 228, 4, 31,
        123, 67, 140, 84, 64, 41, 198, 227, 221, 20, 188, 252, 70, 20, 81, 138, 210, 247, 230, 16,
        233, 229, 154,
    ];

    fn test_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
            enc_key: Box::pin(ENC_KEY.into()),
            mac_key: Box::pin(MAC_KEY.into()),
        })
    }

    #[test]
    #[ignore = "used to generate the test vector constant above; not a unit test"]
    fn generate_test_vectors() {
        let key = test_key();
        let out = encrypt_all(&key, PLAINTEXT, 20);
        println!("const STREAM_TEST_VECTOR: &[u8] = &{:?};", out);
    }

    fn encrypt_all(key: &SymmetricCryptoKey, plaintext: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut encryptor = StreamingAes256CbcHmacEncryptor::try_new(key)
            .ok()
            .expect("encryptor construction");

        let mut plaintext_buffer = plaintext.to_vec();
        let mut ciphertext_buffer = Vec::new();

        loop {
            let chunk = plaintext_buffer
                .drain(..chunk_size.min(plaintext_buffer.len()))
                .collect::<Vec<u8>>();
            match encryptor.update(&chunk, plaintext_buffer.is_empty()) {
                ChunkEncryptionResult::NeedMoreData => {}
                ChunkEncryptionResult::EncryptedChunk(bytes) => {
                    ciphertext_buffer.extend_from_slice(&bytes);
                }
                ChunkEncryptionResult::FinalEncryptedChunk(bytes) => {
                    ciphertext_buffer.extend_from_slice(&bytes);
                    break;
                }
                ChunkEncryptionResult::Error => panic!("encryption error"),
            };
        }

        ciphertext_buffer
    }

    fn decrypt_all(key: &SymmetricCryptoKey, ciphertext: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut decryptor = StreamingAes256CbcHmacDecryptor::try_new(key)
            .ok()
            .expect("decryptor construction");

        let mut ciphertext_buffer = ciphertext.to_vec();
        let mut plaintext_buffer = Vec::new();

        loop {
            let chunk = ciphertext_buffer
                .drain(..chunk_size.min(ciphertext_buffer.len()))
                .collect::<Vec<u8>>();
            match decryptor.update(&chunk, ciphertext_buffer.is_empty()) {
                ChunkDecryptionResult::NeedMoreData => {}
                ChunkDecryptionResult::DecryptedChunk(bytes) => {
                    plaintext_buffer.extend_from_slice(&bytes);
                }
                ChunkDecryptionResult::FinalDecryptedChunk(bytes) => {
                    plaintext_buffer.extend_from_slice(&bytes);
                    break;
                }
                ChunkDecryptionResult::Error => panic!("decryption error"),
            };
        }

        plaintext_buffer
    }

    #[test]
    fn streaming_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = PLAINTEXT;
        let ciphertext = encrypt_all(&key, plaintext, 11);
        let roundtripped = decrypt_all(&key, &ciphertext, 9);

        assert_eq!(roundtripped, plaintext);
    }

    #[test]
    fn streaming_decrypt_with_truncated_ciphertext_fails() {
        let key = test_key();
        let ciphertext = STREAM_TEST_VECTOR;
        let truncated = &ciphertext[..ciphertext.len() - 10];
        let mut dec = StreamingAes256CbcHmacDecryptor::try_new(&key)
            .ok()
            .expect("decryptor construction");
        let result = dec.update(truncated, true);
        assert!(matches!(result, ChunkDecryptionResult::Error));
    }

    #[test]
    fn streaming_decrypt_with_modified_ciphertext_fails() {
        let key = test_key();
        let mut modified = STREAM_TEST_VECTOR.to_vec();
        // Flip a bit in the middle of the stream
        modified[50] ^= 0b0000_0001;
        let mut dec = StreamingAes256CbcHmacDecryptor::try_new(&key)
            .ok()
            .expect("decryptor construction");
        let result = dec.update(&modified, true);
        assert!(matches!(result, ChunkDecryptionResult::Error));
    }

    #[test]
    fn streaming_decrypt_with_modified_header_fails() {
        let key = test_key();
        let mut modified = STREAM_TEST_VECTOR.to_vec();
        // Flip a bit in the header (the IV)
        modified[5] ^= 0b0000_0001;
        let mut dec = StreamingAes256CbcHmacDecryptor::try_new(&key)
            .ok()
            .expect("decryptor construction");
        let result = dec.update(&modified, true);
        assert!(matches!(result, ChunkDecryptionResult::Error));
    }
}
