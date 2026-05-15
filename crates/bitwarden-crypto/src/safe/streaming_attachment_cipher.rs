//! Streaming AES-256-CBC + HMAC primitives for the attachment-upgrade pipeline.
//!
//! [`StreamingAttachmentDecryptor::update`] emits plaintext bytes *before* the HMAC is
//! verified by [`StreamingAttachmentDecryptor::finalize`]. Callers MUST NOT act on those
//! bytes (upload, persist, display) until `finalize` returns `Ok`.

use crate::{
    CryptoError,
    aes::{
        StreamingAes256CbcHmacDecryptor, StreamingAes256CbcHmacEncryptor, StreamingEncryptFinal,
    },
};

/// IV + MAC + trailing ciphertext produced by [`StreamingAttachmentEncryptor::finalize`].
pub struct StreamingAttachmentFinal {
    /// 16-byte AES-CBC IV.
    pub iv: [u8; 16],
    /// 32-byte HMAC-SHA256 tag over IV + ciphertext.
    pub mac: [u8; 32],
    /// PKCS7 mandates a final padding block even when input is block-aligned, so this is
    /// always at least 16 bytes.
    pub trailing_ciphertext: Vec<u8>,
}

impl From<StreamingEncryptFinal> for StreamingAttachmentFinal {
    fn from(value: StreamingEncryptFinal) -> Self {
        Self {
            iv: value.iv,
            mac: value.mac,
            trailing_ciphertext: value.trailing_ciphertext,
        }
    }
}

/// Streaming AES-256-CBC + HMAC-SHA256 decryptor.
pub struct StreamingAttachmentDecryptor(StreamingAes256CbcHmacDecryptor);

impl StreamingAttachmentDecryptor {
    pub(crate) fn new(inner: StreamingAes256CbcHmacDecryptor) -> Self {
        Self(inner)
    }

    /// Feeds a ciphertext chunk; returns any plaintext bytes ready to emit (unauthenticated
    /// until [`Self::finalize`] returns `Ok`).
    pub fn update(&mut self, ciphertext_chunk: &[u8]) -> Vec<u8> {
        self.0.update(ciphertext_chunk)
    }

    /// Verifies the HMAC and returns the final plaintext bytes (PKCS7-unpadded).
    pub fn finalize(self, expected_mac: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        self.0.finalize(expected_mac)
    }
}

/// Streaming AES-256-CBC + HMAC-SHA256 encryptor.
pub struct StreamingAttachmentEncryptor(StreamingAes256CbcHmacEncryptor);

impl StreamingAttachmentEncryptor {
    pub(crate) fn new(inner: StreamingAes256CbcHmacEncryptor) -> Self {
        Self(inner)
    }

    /// Feeds a plaintext chunk; returns any ciphertext blocks ready to emit.
    pub fn update(&mut self, plaintext_chunk: &[u8]) -> Vec<u8> {
        self.0.update(plaintext_chunk)
    }

    /// Encrypts the final PKCS7-padded block(s) and returns IV + MAC + trailing ciphertext.
    pub fn finalize(self) -> StreamingAttachmentFinal {
        self.0.finalize().into()
    }
}
