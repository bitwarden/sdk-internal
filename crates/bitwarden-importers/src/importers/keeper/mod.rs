//! Keeper "direct" importer support.
//!
//! The Keeper direct importer logs into Keeper's API and decrypts the vault on-device. This module
//! holds the Rust port of its access layer, beginning with the cryptography ([`crypto`]). The
//! remaining access layer (vault, client, socket, keys) is still TypeScript in the `clients` repo
//! and calls into this crate through the WASM / UniFFI bindings while it is migrated incrementally.

pub mod crypto;

pub use crypto::KeeperRecordKeyType;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::ImportError;

/// A generated P-256 key pair for Keeper's ECC scheme.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi)
)]
pub struct KeeperEcKeyPair {
    /// PKCS#8 DER-encoded private key.
    pub private_key: Vec<u8>,
    /// Uncompressed SEC1 public key (`0x04 || X || Y`, 65 bytes).
    pub public_key: Vec<u8>,
}

impl From<crypto::EcKeyPair> for KeeperEcKeyPair {
    fn from(value: crypto::EcKeyPair) -> Self {
        Self {
            private_key: value.private_key,
            public_key: value.public_key,
        }
    }
}

/// Stateless client exposing Keeper's importer cryptography to other platforms.
///
/// These primitives implement Keeper's wire formats (see [`crypto`]) so the still-TypeScript Keeper
/// access layer can call the Rust implementation while it is ported incrementally. The client holds
/// no state and no Bitwarden keys.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KeeperCryptoClient;

impl Default for KeeperCryptoClient {
    fn default() -> Self {
        KeeperCryptoClient
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl KeeperCryptoClient {
    /// Create a new stateless Keeper crypto client.
    ///
    /// Exposed as a constructor so the (still-TypeScript) Keeper access layer can construct it
    /// directly; it holds no state and no Bitwarden keys.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        KeeperCryptoClient
    }

    /// Generate `length` cryptographically random bytes.
    pub fn get_random_bytes(&self, length: usize) -> Vec<u8> {
        crypto::get_random_bytes(length)
    }

    /// Generate a new 32-byte AES encryption key.
    pub fn generate_encryption_key(&self) -> Vec<u8> {
        crypto::generate_encryption_key().to_vec()
    }

    /// Decrypt an "aes-v1" packet (AES-256-CBC, PKCS#7, unauthenticated). Packet: `IV(16) || ct`.
    pub fn decrypt_aes_v1(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_aes_v1(&data, &key)?)
    }

    /// Encrypt an "aes-v2" packet (AES-256-GCM). Output: `nonce(12) || ct || tag(16)`.
    ///
    /// A fresh random 12-byte nonce is always generated; the nonce is never caller-supplied, which
    /// makes nonce reuse (a catastrophic failure for AES-GCM) impossible across this boundary.
    pub fn encrypt_aes_v2(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::encrypt_aes_v2(&data, &key)?)
    }

    /// Decrypt an "aes-v2" packet (AES-256-GCM). Packet: `nonce(12) || ct || tag(16)`.
    pub fn decrypt_aes_v2(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_aes_v2(&data, &key)?)
    }

    /// Encrypt with an RSA public key (PKCS#1 v1.5). `public_key` is PKCS#1 DER.
    pub fn encrypt_rsa(&self, data: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::encrypt_rsa(&data, &public_key)?)
    }

    /// Decrypt with an RSA private key (PKCS#1 v1.5). `private_key` is PKCS#1 DER.
    pub fn decrypt_rsa(&self, data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_rsa(&data, &private_key)?)
    }

    /// Generate a new P-256 key pair for Keeper's ECC scheme.
    pub fn generate_ec_key(&self) -> Result<KeeperEcKeyPair, ImportError> {
        Ok(crypto::generate_ec_key()?.into())
    }

    /// Encrypt for an EC public key (ECDH-P256 → AES-GCM). `public_key` is an uncompressed SEC1
    /// point. Output: `ephemeralPublic(65) || aes-v2 packet`.
    pub fn encrypt_ec(&self, data: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::encrypt_ec(&data, &public_key)?)
    }

    /// Decrypt an EC-encrypted packet. `private_key` is PKCS#8 DER.
    pub fn decrypt_ec(&self, data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_ec(&data, &private_key)?)
    }

    /// Derive a Keeper master key from a password (PBKDF2-HMAC-SHA256, 32 bytes).
    pub fn derive_key_v1(&self, password: String, salt: Vec<u8>, iterations: u32) -> Vec<u8> {
        crypto::derive_key_v1(&password, &salt, iterations).to_vec()
    }

    /// Derive Keeper's v1 auth hash: `SHA-256(derive_key_v1(...))`.
    pub fn derive_v1_key_hash(&self, password: String, salt: Vec<u8>, iterations: u32) -> Vec<u8> {
        crypto::derive_v1_key_hash(&password, &salt, iterations)
    }

    /// Derive a data key from a Keeper `encryptionParams` blob.
    pub fn decrypt_encryption_params(
        &self,
        password: String,
        encryption_params: Vec<u8>,
    ) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_encryption_params(&password, &encryption_params)?.to_vec())
    }

    /// Decrypt a record/folder key according to its [`KeeperRecordKeyType`].
    pub fn decrypt_keeper_key(
        &self,
        encrypted_key: Vec<u8>,
        key_type: KeeperRecordKeyType,
        data_key: Vec<u8>,
        rsa_private_key: Option<Vec<u8>>,
        ec_private_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::decrypt_keeper_key(
            &encrypted_key,
            key_type,
            &data_key,
            rsa_private_key.as_deref(),
            ec_private_key.as_deref(),
        )?
        .to_vec())
    }

    /// Encode bytes as unpadded URL-safe base64.
    pub fn base64_url_encode(&self, data: Vec<u8>) -> String {
        crypto::base64_url_encode(&data)
    }

    /// Decode unpadded URL-safe base64.
    pub fn base64_url_decode(&self, text: String) -> Result<Vec<u8>, ImportError> {
        Ok(crypto::base64_url_decode(&text)?)
    }
}
