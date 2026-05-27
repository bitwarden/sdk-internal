use bitwarden_crypto::{
    AttachmentDecryptor, AttachmentEncryptor, BitwardenLegacyKeyBytes, CryptoError,
    SymmetricCryptoKey,
};
use wasm_bindgen::prelude::*;

/// Chunked AES-256-CBC + HMAC-SHA256 attachment encryptor exposed to JS.
///
/// Usage: construct with a 64-byte AES-CBC-HMAC key, feed plaintext chunks via
/// [`Self::update`], then call [`Self::finalize`] to retrieve the wire payload
/// (`0x02 || IV || MAC || ciphertext`).
#[wasm_bindgen]
pub struct WasmAttachmentEncryptor(AttachmentEncryptor);

#[wasm_bindgen]
impl WasmAttachmentEncryptor {
    /// Construct an encryptor. `key` is the 64-byte AES-CBC-HMAC key encoding.
    #[wasm_bindgen(constructor)]
    pub fn new(key: Vec<u8>) -> Result<WasmAttachmentEncryptor, CryptoError> {
        let key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(key))?;
        Ok(Self(AttachmentEncryptor::new(&key)?))
    }

    /// Feed a plaintext chunk. Returns any wire bytes that have become
    /// available (empty for AES-CBC-HMAC until `finalize`).
    pub fn update(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        self.0.update(&chunk)
    }

    /// Finalize encryption and return the terminal wire payload
    /// (`0x02 || IV || MAC || ciphertext`).
    pub fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
        self.0.finalize()
    }
}

/// Chunked AES-256-CBC + HMAC-SHA256 attachment decryptor exposed to JS.
///
/// The discriminator byte at the start of the wire stream is consumed by
/// [`Self::update`] — callers do not need to peel it off. Plaintext returned
/// from `update` is unauthenticated until [`Self::finalize`] returns
/// successfully; callers must withhold downstream trust until then.
#[wasm_bindgen]
pub struct WasmAttachmentDecryptor(AttachmentDecryptor);

#[wasm_bindgen]
impl WasmAttachmentDecryptor {
    /// Construct a decryptor. `key` is the 64-byte AES-CBC-HMAC key encoding.
    #[wasm_bindgen(constructor)]
    pub fn new(key: Vec<u8>) -> Result<WasmAttachmentDecryptor, CryptoError> {
        let key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(key))?;
        Ok(Self(AttachmentDecryptor::new(key)?))
    }

    /// Feed a wire-stream chunk. Returns any plaintext that has become
    /// available — unauthenticated until `finalize` returns successfully.
    pub fn update(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        self.0.update(&chunk)
    }

    /// Finalize decryption and return the terminal authenticated plaintext.
    /// Errors on truncated input or HMAC mismatch.
    pub fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
        self.0.finalize()
    }
}
