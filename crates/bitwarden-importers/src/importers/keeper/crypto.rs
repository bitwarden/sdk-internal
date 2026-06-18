//! Keeper "direct" importer cryptography.
//!
//! This is a byte-for-byte port of the Keeper access layer's `crypto.ts`. It implements
//! **Keeper's** competitor wire formats, not Bitwarden's, so it deliberately does **not** live in
//! `bitwarden-crypto`: the formats are unauthenticated AES-CBC ("aes-v1"), AES-GCM with a prepended
//! nonce ("aes-v2"), RSA PKCS#1 v1.5, an ECDH-P256 → SHA-256 → AES-GCM scheme, and Keeper's custom
//! `encryptionParams` blob. Where a primitive is standard we reuse `bitwarden_crypto`
//! (`pbkdf2`) and otherwise use the RustCrypto crates directly.
//!
//! Every function here must stay compatible with data produced by Keeper's clients; do not change
//! the formats.

use aes::cipher::{
    BlockModeDecrypt, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use bitwarden_crypto::pbkdf2;
use p256::{
    PublicKey, SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::Rng;
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// AES symmetric key size used by Keeper (256-bit).
const KEEPER_KEY_SIZE: usize = 32;
/// AES-CBC block size / IV size.
const AES_BLOCK_SIZE: usize = 16;
/// AES-GCM nonce size used by Keeper.
const AES_GCM_NONCE_SIZE: usize = 12;
/// Length of an uncompressed SEC1 P-256 public key (`0x04 || X || Y`).
const EC_PUBLIC_KEY_SIZE: usize = 65;
/// Total length of a valid Keeper `encryptionParams` blob: version(1) + iterations(3) + salt(16) +
/// iv(16) + two 32-byte key blocks(64).
const ENCRYPTION_PARAMS_SIZE: usize = 1 + 3 + 16 + 16 + 64;

/// Errors produced by the Keeper crypto layer.
///
/// Messages are intentionally coarse and never include key material, plaintext or ciphertext, so an
/// error can be surfaced to a client or log without leaking secrets.
#[derive(Debug, thiserror::Error)]
pub enum KeeperCryptoError {
    /// Decryption or authentication failed (bad key, tampered ciphertext, or invalid padding).
    #[error("Keeper decryption failed")]
    Decryption,
    /// A key could not be parsed or has the wrong size.
    #[error("Invalid Keeper key material")]
    InvalidKey,
    /// The input was malformed (too short, wrong length, or not a valid encoding).
    #[error("Malformed Keeper input")]
    InvalidData,
    /// A Keeper `encryptionParams` blob was corrupted or failed its integrity check.
    #[error("Corrupted Keeper encryption parameters")]
    CorruptEncryptionParams,
    /// The record key type is not supported for decryption.
    #[error("Unsupported Keeper record key type")]
    UnsupportedKeyType,
}

/// Keeper record key types, mirroring `RecordKeyType` in Keeper's `record.proto`.
///
/// The numeric values are part of Keeper's wire format and must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum KeeperRecordKeyType {
    /// No key present; cannot be decrypted.
    NoKey = 0,
    /// Encrypted with the data key using AES-CBC ("aes-v1").
    EncryptedByDataKey = 1,
    /// Encrypted with the account's RSA public key (PKCS#1 v1.5).
    EncryptedByPublicKey = 2,
    /// Encrypted with the data key using AES-GCM ("aes-v2").
    EncryptedByDataKeyGcm = 3,
    /// Encrypted with the account's EC public key (ECDH-P256 → AES-GCM).
    EncryptedByPublicKeyEcc = 4,
    /// Encrypted with the root key using AES-CBC. Not supported here.
    EncryptedByRootKeyCbc = 5,
    /// Encrypted with the root key using AES-GCM. Not supported here.
    EncryptedByRootKeyGcm = 6,
}

/// A freshly generated P-256 key pair: PKCS#8 DER private key and uncompressed SEC1 public key.
pub struct EcKeyPair {
    /// PKCS#8 DER-encoded private key.
    pub private_key: Vec<u8>,
    /// Uncompressed SEC1 public key (`0x04 || X || Y`, 65 bytes).
    pub public_key: Vec<u8>,
}

/// Generate `length` cryptographically secure random bytes.
pub fn get_random_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Generate a new 32-byte AES encryption key.
pub fn generate_encryption_key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(get_random_bytes(KEEPER_KEY_SIZE))
}

/// Decrypt an "aes-v1" packet: AES-256-CBC with PKCS#7 padding and no authentication (no MAC).
///
/// The packet is `IV(16) || ciphertext`. Keeper aes-v1 is unauthenticated, so a successful decrypt
/// does not prove integrity — callers must not rely on this for tamper detection.
pub fn decrypt_aes_v1(data: &[u8], key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    if key.len() != KEEPER_KEY_SIZE {
        return Err(KeeperCryptoError::InvalidKey);
    }
    if data.len() < AES_BLOCK_SIZE {
        return Err(KeeperCryptoError::InvalidData);
    }
    let (iv, ciphertext) = data.split_at(AES_BLOCK_SIZE);
    let mut buf = ciphertext.to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| KeeperCryptoError::InvalidKey)?
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| KeeperCryptoError::Decryption)?;
    let len = decrypted.len();
    buf.truncate(len);
    Ok(buf)
}

/// Encrypt an "aes-v2" packet: AES-256-GCM. The output is `nonce(12) || ciphertext || tag(16)`.
///
/// A fresh random 12-byte nonce is always generated — there is intentionally no way to supply one,
/// so nonce reuse (a catastrophic failure for AES-GCM) cannot happen.
pub fn encrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    encrypt_aes_v2_with_nonce(data, key, &nonce)
}

/// Encrypt an "aes-v2" packet with an explicit nonce. Kept private and used only by
/// [`encrypt_aes_v2`] (random nonce) and the known-answer tests, so the nonce-reuse hazard is never
/// exposed to callers.
fn encrypt_aes_v2_with_nonce(
    data: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, KeeperCryptoError> {
    if key.len() != KEEPER_KEY_SIZE {
        return Err(KeeperCryptoError::InvalidKey);
    }
    let nonce_bytes: [u8; AES_GCM_NONCE_SIZE] = nonce
        .try_into()
        .map_err(|_| KeeperCryptoError::InvalidData)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let nonce_arr = Nonce::<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize>::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce_arr, data)
        .map_err(|_| KeeperCryptoError::Decryption)?;
    let mut out = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an "aes-v2" packet: AES-256-GCM where the packet is `nonce(12) || ciphertext ||
/// tag(16)`.
///
/// Unlike aes-v1 this is authenticated: a tampered packet fails with
/// [`KeeperCryptoError::Decryption`].
pub fn decrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    if key.len() != KEEPER_KEY_SIZE {
        return Err(KeeperCryptoError::InvalidKey);
    }
    if data.len() < AES_GCM_NONCE_SIZE {
        return Err(KeeperCryptoError::InvalidData);
    }
    let (nonce_bytes, ciphertext) = data.split_at(AES_GCM_NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let nonce_arr = Nonce::<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize>::try_from(nonce_bytes)
        .map_err(|_| KeeperCryptoError::InvalidData)?;
    cipher
        .decrypt(&nonce_arr, ciphertext)
        .map_err(|_| KeeperCryptoError::Decryption)
}

/// Encrypt `data` with an RSA public key using PKCS#1 v1.5 padding.
///
/// `public_key` is a DER-encoded PKCS#1 `RSAPublicKey` (the format Keeper ships its server keys
/// in).
pub fn encrypt_rsa(data: &[u8], public_key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    let key =
        RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let mut rng = rand::rng();
    key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|_| KeeperCryptoError::Decryption)
}

/// Decrypt `data` with an RSA private key using PKCS#1 v1.5 padding.
///
/// `private_key` is a DER-encoded PKCS#1 `RSAPrivateKey`.
pub fn decrypt_rsa(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    let key =
        RsaPrivateKey::from_pkcs1_der(private_key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    key.decrypt(Pkcs1v15Encrypt, data)
        .map_err(|_| KeeperCryptoError::Decryption)
}

/// Generate a new P-256 key pair for Keeper's ECC scheme.
pub fn generate_ec_key() -> Result<EcKeyPair, KeeperCryptoError> {
    let secret = SecretKey::generate_from_rng(&mut rand::rng());
    let private_key = secret
        .to_pkcs8_der()
        .map_err(|_| KeeperCryptoError::InvalidKey)?
        .as_bytes()
        .to_vec();
    let public_key = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
    Ok(EcKeyPair {
        private_key,
        public_key,
    })
}

/// Derive Keeper's ECDH content-encryption-key: ECDH(P-256) shared X coordinate, then SHA-256.
fn derive_ecdh_key(public: &PublicKey, secret: &SecretKey) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let hash = Sha256::digest(shared.raw_secret_bytes());
    Zeroizing::new(hash.into())
}

/// Encrypt `data` for an EC public key (Keeper's ECC scheme).
///
/// An ephemeral key pair is generated; the shared key is `SHA-256(ECDH(recipient, ephemeral))` and
/// the payload is sealed with aes-v2. The output is `ephemeralPublic(65) || aes-v2 packet`.
///
/// `public_key` is an uncompressed SEC1 point (`0x04 || X || Y`, 65 bytes).
pub fn encrypt_ec(data: &[u8], public_key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    let recipient =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let ephemeral = SecretKey::generate_from_rng(&mut rand::rng());
    let encryption_key = derive_ecdh_key(&recipient, &ephemeral);
    let encrypted = encrypt_aes_v2(data, encryption_key.as_slice())?;
    let ephemeral_public = ephemeral.public_key().to_sec1_point(false);

    let mut out = Vec::with_capacity(ephemeral_public.as_bytes().len() + encrypted.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Decrypt an EC-encrypted packet (Keeper's ECC scheme).
///
/// The packet is `ephemeralPublic(65) || aes-v2 packet`. `private_key` is a PKCS#8 DER P-256 key.
pub fn decrypt_ec(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, KeeperCryptoError> {
    if data.len() < EC_PUBLIC_KEY_SIZE {
        return Err(KeeperCryptoError::InvalidData);
    }
    let secret =
        SecretKey::from_pkcs8_der(private_key).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let (ephemeral_bytes, encrypted) = data.split_at(EC_PUBLIC_KEY_SIZE);
    let ephemeral_public =
        PublicKey::from_sec1_bytes(ephemeral_bytes).map_err(|_| KeeperCryptoError::InvalidKey)?;
    let encryption_key = derive_ecdh_key(&ephemeral_public, &secret);
    decrypt_aes_v2(encrypted, encryption_key.as_slice())
}

/// Derive a Keeper master key from a password using PBKDF2-HMAC-SHA256 (32-byte output).
pub fn derive_key_v1(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(pbkdf2(password.as_bytes(), salt, iterations))
}

/// Derive Keeper's v1 auth hash: `SHA-256(derive_key_v1(password, salt, iterations))`.
pub fn derive_v1_key_hash(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let key = derive_key_v1(password, salt, iterations);
    Sha256::digest(key.as_slice()).to_vec()
}

/// Decrypt 64 bytes of AES-256-CBC ciphertext with no padding.
///
/// Keeper's `encryptionParams` blob holds exactly two 32-byte blocks (a known multiple of the AES
/// block size), so PKCS#7 padding is never present. The RustCrypto `cbc` crate supports a
/// no-padding mode directly, so unlike the TypeScript original no manual padding trick is needed.
fn decrypt_aes_no_padding(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, KeeperCryptoError> {
    let mut buf = data.to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| KeeperCryptoError::InvalidKey)?
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| KeeperCryptoError::Decryption)?;
    let len = decrypted.len();
    buf.truncate(len);
    Ok(buf)
}

/// Derive a data key from Keeper's `encryptionParams` blob.
///
/// The blob is laid out as `version(1) || iterations(3, big-endian) || salt(16) || iv(16) ||
/// data(64)`. The iterations and salt derive a key (PBKDF2) used to AES-CBC-decrypt (no padding)
/// the 64-byte data into two 32-byte blocks that must be identical; the shared value is the data
/// key. The version byte must be `1`.
pub fn decrypt_encryption_params(
    password: &str,
    encryption_params: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeeperCryptoError> {
    if encryption_params.first() != Some(&1) {
        return Err(KeeperCryptoError::CorruptEncryptionParams);
    }
    if encryption_params.len() != ENCRYPTION_PARAMS_SIZE {
        return Err(KeeperCryptoError::CorruptEncryptionParams);
    }

    let iterations = (u32::from(encryption_params[1]) << 16)
        | (u32::from(encryption_params[2]) << 8)
        | u32::from(encryption_params[3]);
    let salt = &encryption_params[4..20];
    let key = derive_key_v1(password, salt, iterations);

    let iv = &encryption_params[20..36];
    let encrypted_data = &encryption_params[36..];
    let decrypted = decrypt_aes_no_padding(encrypted_data, key.as_slice(), iv)?;

    let first = &decrypted[0..32];
    let second = &decrypted[32..64];
    // Constant-time comparison so the running time does not reveal where (or whether) the two
    // blocks differ.
    if first.ct_eq(second).unwrap_u8() != 1 {
        return Err(KeeperCryptoError::CorruptEncryptionParams);
    }

    Ok(Zeroizing::new(first.to_vec()))
}

/// Decrypt a record/folder key according to its [`KeeperRecordKeyType`].
///
/// `rsa_private_key` (PKCS#1 DER) is required for [`KeeperRecordKeyType::EncryptedByPublicKey`] and
/// `ec_private_key` (PKCS#8 DER) for [`KeeperRecordKeyType::EncryptedByPublicKeyEcc`]. Root-key
/// types and `NoKey` are not supported and yield [`KeeperCryptoError::UnsupportedKeyType`].
pub fn decrypt_keeper_key(
    encrypted_key: &[u8],
    key_type: KeeperRecordKeyType,
    data_key: &[u8],
    rsa_private_key: Option<&[u8]>,
    ec_private_key: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, KeeperCryptoError> {
    let key = match key_type {
        KeeperRecordKeyType::EncryptedByDataKey => decrypt_aes_v1(encrypted_key, data_key)?,
        KeeperRecordKeyType::EncryptedByPublicKey => {
            let private_key = rsa_private_key.ok_or(KeeperCryptoError::InvalidKey)?;
            decrypt_rsa(encrypted_key, private_key)?
        }
        KeeperRecordKeyType::EncryptedByDataKeyGcm => decrypt_aes_v2(encrypted_key, data_key)?,
        KeeperRecordKeyType::EncryptedByPublicKeyEcc => {
            let private_key = ec_private_key.ok_or(KeeperCryptoError::InvalidKey)?;
            decrypt_ec(encrypted_key, private_key)?
        }
        KeeperRecordKeyType::NoKey
        | KeeperRecordKeyType::EncryptedByRootKeyCbc
        | KeeperRecordKeyType::EncryptedByRootKeyGcm => {
            return Err(KeeperCryptoError::UnsupportedKeyType);
        }
    };
    Ok(Zeroizing::new(key))
}

/// Encode bytes as unpadded URL-safe base64 (Keeper's `base64UrlEncode`).
pub fn base64_url_encode(data: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(data)
}

/// Decode unpadded URL-safe base64 (Keeper's `base64UrlDecode`).
///
/// Any trailing `=` padding is tolerated to match the lenient behaviour of the TypeScript original.
pub fn base64_url_decode(text: &str) -> Result<Vec<u8>, KeeperCryptoError> {
    let trimmed = text.trim_end_matches('=');
    data_encoding::BASE64URL_NOPAD
        .decode(trimmed.as_bytes())
        .map_err(|_| KeeperCryptoError::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real Keeper server RSA public key (keyId 1) and EC public key (keyId 7), to prove the
    // PKCS#1 / SEC1 parsers accept Keeper's actual key formats.
    const KEEPER_RSA_KEY_1: &str = "MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfHOOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInnj4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-VxIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB";
    const KEEPER_EC_KEY_7: &str =
        "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM";

    #[test]
    fn aes_v2_round_trip() {
        let key = [7u8; 32];
        let plaintext = b"keeper aes-v2 round trip";
        let packet = encrypt_aes_v2(plaintext, &key).unwrap();
        // nonce(12) || ciphertext(len) || tag(16)
        assert_eq!(packet.len(), 12 + plaintext.len() + 16);
        let decrypted = decrypt_aes_v2(&packet, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_v2_known_answer_empty() {
        // NIST AES-256-GCM KAT: key=0^256, iv=0^96, pt empty => tag
        // 530f8afbc74536b9a963b4f1c4cb738b
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let packet = encrypt_aes_v2_with_nonce(&[], &key, &nonce).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"530f8afbc74536b9a963b4f1c4cb738b")
            .unwrap();
        // packet = nonce || (empty ciphertext) || tag
        assert_eq!(&packet[..12], &nonce);
        assert_eq!(&packet[12..], expected.as_slice());
    }

    #[test]
    fn aes_v2_known_answer_block() {
        // NIST AES-256-GCM KAT: key=0^256, iv=0^96, pt=0^128
        //   ct = cea7403d4d606b6e074ec5d3baf39d18, tag = d0d1c8a799996bf0265b98b5d48ab919
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let packet = encrypt_aes_v2_with_nonce(&[0u8; 16], &key, &nonce).unwrap();
        let expected_ct = data_encoding::HEXLOWER
            .decode(b"cea7403d4d606b6e074ec5d3baf39d18")
            .unwrap();
        let expected_tag = data_encoding::HEXLOWER
            .decode(b"d0d1c8a799996bf0265b98b5d48ab919")
            .unwrap();
        assert_eq!(&packet[12..28], expected_ct.as_slice());
        assert_eq!(&packet[28..], expected_tag.as_slice());
    }

    #[test]
    fn aes_v2_rejects_tampered_ciphertext() {
        let key = [3u8; 32];
        let mut packet = encrypt_aes_v2(b"secret", &key).unwrap();
        // Flip a bit in the tag region.
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert!(matches!(
            decrypt_aes_v2(&packet, &key),
            Err(KeeperCryptoError::Decryption)
        ));
    }

    #[test]
    fn aes_v2_rejects_wrong_key_size() {
        assert!(matches!(
            encrypt_aes_v2(b"x", &[0u8; 16]),
            Err(KeeperCryptoError::InvalidKey)
        ));
        assert!(matches!(
            decrypt_aes_v2(b"012345678901xxxxxxxxxxxxxxxxxxxx", &[0u8; 31]),
            Err(KeeperCryptoError::InvalidKey)
        ));
    }

    #[test]
    fn aes_v1_round_trip() {
        // Produce a valid aes-v1 packet (IV || AES-256-CBC/PKCS7) and decrypt it.
        use aes::cipher::BlockModeEncrypt;
        let key = [9u8; 32];
        let iv = [1u8; 16];
        let plaintext = b"keeper aes-v1 unauthenticated payload";
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(plaintext);
        let mut packet = iv.to_vec();
        packet.extend_from_slice(&ciphertext);

        let decrypted = decrypt_aes_v1(&packet, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pbkdf2_known_answer() {
        // PBKDF2-HMAC-SHA256, password="password", salt="salt", c=1, dkLen=32
        let key = derive_key_v1("password", b"salt", 1);
        let expected = data_encoding::HEXLOWER
            .decode(b"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
            .unwrap();
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    fn derive_v1_key_hash_is_sha256_of_key() {
        let key = derive_key_v1("hunter2", b"somesalt", 1000);
        let expected = Sha256::digest(key.as_slice()).to_vec();
        assert_eq!(derive_v1_key_hash("hunter2", b"somesalt", 1000), expected);
    }

    #[test]
    fn base64_url_round_trip_and_keeper_keys() {
        let bytes = [0xfb, 0xff, 0x00, 0x10, 0x3e, 0x7d];
        let encoded = base64_url_encode(&bytes);
        // URL-safe, unpadded.
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
        assert_eq!(base64_url_decode(&encoded).unwrap(), bytes);

        // A real Keeper EC key decodes to a 65-byte uncompressed point.
        let ec = base64_url_decode(KEEPER_EC_KEY_7).unwrap();
        assert_eq!(ec.len(), 65);
        assert_eq!(ec[0], 0x04);

        // Tolerates trailing padding.
        assert_eq!(base64_url_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_url_decode("YWJj==").unwrap(), b"abc");
    }

    #[test]
    fn rsa_parses_real_keeper_key_and_round_trips() {
        // Real Keeper public key parses and encrypts to a 2048-bit (256-byte) block.
        let pub_der = base64_url_decode(KEEPER_RSA_KEY_1).unwrap();
        let encrypted = encrypt_rsa(b"data key", &pub_der).unwrap();
        assert_eq!(encrypted.len(), 256);

        // Self round trip against a generated key (we have no Keeper private key).
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let mut rng = rand::rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let priv_der = private.to_pkcs1_der().unwrap();
        let pub_der = public.to_pkcs1_der().unwrap();

        let plaintext = b"a record key";
        let ct = encrypt_rsa(plaintext, pub_der.as_bytes()).unwrap();
        let pt = decrypt_rsa(&ct, priv_der.as_bytes()).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn ec_round_trip() {
        let pair = generate_ec_key().unwrap();
        assert_eq!(pair.public_key.len(), 65);
        assert_eq!(pair.public_key[0], 0x04);

        let plaintext = b"an ec-protected record key";
        let packet = encrypt_ec(plaintext, &pair.public_key).unwrap();
        // ephemeral public(65) || nonce(12) || ct || tag(16)
        assert_eq!(packet.len(), 65 + 12 + plaintext.len() + 16);
        let decrypted = decrypt_ec(&packet, &pair.private_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ec_rejects_wrong_private_key() {
        let pair = generate_ec_key().unwrap();
        let other = generate_ec_key().unwrap();
        let packet = encrypt_ec(b"secret", &pair.public_key).unwrap();
        assert!(decrypt_ec(&packet, &other.private_key).is_err());
    }

    /// Build a valid `encryptionParams` blob the way Keeper would, so we can test decryption.
    fn make_encryption_params(
        password: &str,
        iterations: u32,
        salt: &[u8; 16],
        data_key: &[u8; 32],
    ) -> Vec<u8> {
        use aes::cipher::BlockModeEncrypt;
        let derived = derive_key_v1(password, salt, iterations);
        let iv = [0x42u8; 16];
        // Two identical 32-byte blocks, AES-CBC no padding.
        let mut blocks = data_key.to_vec();
        blocks.extend_from_slice(data_key);
        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(derived.as_slice(), &iv)
            .unwrap()
            .encrypt_padded_vec::<NoPadding>(&blocks);

        let mut params = vec![
            1u8, // version
            (iterations >> 16) as u8,
            (iterations >> 8) as u8,
            iterations as u8,
        ];
        params.extend_from_slice(salt);
        params.extend_from_slice(&iv);
        params.extend_from_slice(&encrypted);
        params
    }

    #[test]
    fn decrypt_encryption_params_recovers_data_key() {
        let data_key = [0x11u8; 32];
        let params = make_encryption_params("master-password", 1000, &[0x07u8; 16], &data_key);
        let recovered = decrypt_encryption_params("master-password", &params).unwrap();
        assert_eq!(recovered.as_slice(), &data_key);
    }

    #[test]
    fn decrypt_encryption_params_rejects_wrong_password() {
        let data_key = [0x11u8; 32];
        let params = make_encryption_params("master-password", 1000, &[0x07u8; 16], &data_key);
        // Wrong password yields mismatched blocks -> CorruptEncryptionParams.
        assert!(matches!(
            decrypt_encryption_params("wrong-password", &params),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
    }

    #[test]
    fn decrypt_encryption_params_rejects_bad_version_and_length() {
        let mut params = make_encryption_params("pw", 100, &[0u8; 16], &[0u8; 32]);
        params[0] = 2;
        assert!(matches!(
            decrypt_encryption_params("pw", &params),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
        assert!(matches!(
            decrypt_encryption_params("pw", &[1u8, 0, 0, 1]),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
    }

    #[test]
    fn decrypt_keeper_key_dispatches() {
        let data_key = [5u8; 32];
        let record_key = [0xABu8; 32];

        // aes-v2 path
        let packet = encrypt_aes_v2(&record_key, &data_key).unwrap();
        let decrypted = decrypt_keeper_key(
            &packet,
            KeeperRecordKeyType::EncryptedByDataKeyGcm,
            &data_key,
            None,
            None,
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), &record_key);

        // aes-v1 path
        use aes::cipher::BlockModeEncrypt;
        let iv = [2u8; 16];
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&data_key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(&record_key);
        let mut v1_packet = iv.to_vec();
        v1_packet.extend_from_slice(&ct);
        let decrypted = decrypt_keeper_key(
            &v1_packet,
            KeeperRecordKeyType::EncryptedByDataKey,
            &data_key,
            None,
            None,
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), &record_key);
    }

    #[test]
    fn decrypt_keeper_key_unsupported_and_missing_keys() {
        let data_key = [0u8; 32];
        assert!(matches!(
            decrypt_keeper_key(&[], KeeperRecordKeyType::NoKey, &data_key, None, None),
            Err(KeeperCryptoError::UnsupportedKeyType)
        ));
        assert!(matches!(
            decrypt_keeper_key(
                &[],
                KeeperRecordKeyType::EncryptedByRootKeyGcm,
                &data_key,
                None,
                None
            ),
            Err(KeeperCryptoError::UnsupportedKeyType)
        ));
        // RSA path with no private key supplied.
        assert!(matches!(
            decrypt_keeper_key(
                &[1, 2, 3],
                KeeperRecordKeyType::EncryptedByPublicKey,
                &data_key,
                None,
                None
            ),
            Err(KeeperCryptoError::InvalidKey)
        ));
    }
}
