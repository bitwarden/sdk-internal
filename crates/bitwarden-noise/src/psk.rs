//! PSK (Pre-Shared Key) Authentication Module
//!
//! Provides utilities for deriving Pre-Shared Keys from passwords
//! for use with Noise Protocol PSK patterns.
//!
//! This uses HKDF-based derivation suitable for device pairing scenarios.

use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::NoiseProtocolError;

/// PSK length in bytes (32 bytes for Noise protocol)
pub const PSK_LENGTH: usize = 32;

/// Salt length in bytes
pub const SALT_LENGTH: usize = 32;

/// Info string used for HKDF derivation
const HKDF_INFO: &[u8] = b"noise-pairing-psk-v1";

/// Generate a random salt for PSK derivation
///
/// Returns a 32-byte random salt suitable for use with [`derive_psk_from_password`].
pub fn generate_psk_salt() -> Result<[u8; SALT_LENGTH], NoiseProtocolError> {
    let mut salt = [0u8; SALT_LENGTH];
    getrandom::getrandom(&mut salt).map_err(|_| NoiseProtocolError::SaltGeneration)?;
    Ok(salt)
}

/// Derive a Pre-Shared Key (PSK) from a password using HKDF
///
/// Uses HKDF with SHA-256 to derive a 32-byte PSK suitable for use
/// with Noise Protocol patterns.
///
/// # Arguments
/// * `password` - The pairing password (typically a short code like "K7X9")
/// * `salt` - Random salt (32 bytes) to prevent rainbow table attacks
///
/// # Returns
/// A 32-byte PSK for Noise protocol
pub fn derive_psk_from_password(
    password: &str,
    salt: &[u8],
) -> Result<[u8; PSK_LENGTH], NoiseProtocolError> {
    if salt.len() != SALT_LENGTH {
        return Err(NoiseProtocolError::BadSaltLength);
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut psk = [0u8; PSK_LENGTH];
    hk.expand(HKDF_INFO, &mut psk)
        .map_err(|_| NoiseProtocolError::PskDerivation)?;

    Ok(psk)
}

/// Metadata encoded in a pairing code
#[derive(Debug, Clone)]
pub struct PairingCodeMetadata {
    /// The salt used for PSK derivation
    pub salt: [u8; SALT_LENGTH],
    /// The username associated with this pairing code
    pub username: String,
}

/// Encode a pairing code that bundles password, salt, and username together
///
/// Format: `password:base64(JSON{s: base64(salt), u: username})`
/// Example: `"K7X9:eyJzIjoiNG44d0YyLi4uIiwidSI6ImFuZGVycyJ9"`
///
/// # Arguments
/// * `password` - The pairing password
/// * `salt` - The PSK salt (32 bytes)
/// * `username` - The username to encode in the pairing code
///
/// # Returns
/// Combined pairing code string
pub fn encode_pairing_code(
    password: &str,
    salt: &[u8; SALT_LENGTH],
    username: &str,
) -> Result<String, NoiseProtocolError> {
    let salt_base64 = STANDARD.encode(salt);

    // Create JSON metadata: {"s": "<salt>", "u": "<username>"}
    let metadata_json = format!(r#"{{"s":"{}","u":"{}"}}"#, salt_base64, username);
    let metadata_base64 = STANDARD.encode(metadata_json.as_bytes());

    Ok(format!("{}:{}", password, metadata_base64))
}

/// Decoded pairing code components
#[derive(Debug, Clone)]
pub struct DecodedPairingCode {
    /// The pairing password
    pub password: String,
    /// The salt for PSK derivation
    pub salt: [u8; SALT_LENGTH],
    /// The username from the pairing code
    pub username: String,
}

/// Decode a pairing code into password, salt, and username components
///
/// # Arguments
/// * `pairing_code` - The combined pairing code string
///
/// # Returns
/// Decoded components including password, salt, and username
pub fn decode_pairing_code(pairing_code: &str) -> Result<DecodedPairingCode, NoiseProtocolError> {
    let parts: Vec<&str> = pairing_code.splitn(2, ':').collect();

    if parts.len() != 2 {
        return Err(NoiseProtocolError::InvalidPairingCodeFormat);
    }

    let password = parts[0];
    let metadata_base64 = parts[1];

    if password.is_empty() {
        return Err(NoiseProtocolError::InvalidPairingCodeFormat);
    }

    // Decode base64 metadata
    let metadata_bytes = STANDARD
        .decode(metadata_base64)
        .map_err(|_| NoiseProtocolError::InvalidPairingCodeMetadata)?;

    let metadata_str = String::from_utf8(metadata_bytes)
        .map_err(|_| NoiseProtocolError::InvalidPairingCodeMetadata)?;

    // Parse JSON manually to avoid serde_json dependency for simple structure
    // Expected format: {"s":"<base64>","u":"<username>"}
    let (salt_base64, username) = parse_metadata_json(&metadata_str)?;

    // Decode salt from base64
    let salt_bytes = STANDARD
        .decode(&salt_base64)
        .map_err(|_| NoiseProtocolError::InvalidPairingCodeMetadata)?;

    if salt_bytes.len() != SALT_LENGTH {
        return Err(NoiseProtocolError::BadSaltLength);
    }

    let mut salt = [0u8; SALT_LENGTH];
    salt.copy_from_slice(&salt_bytes);

    Ok(DecodedPairingCode {
        password: password.to_string(),
        salt,
        username,
    })
}

/// Parse the metadata JSON manually
/// Expected format: {"s":"<base64>","u":"<username>"}
fn parse_metadata_json(json: &str) -> Result<(String, String), NoiseProtocolError> {
    // Simple JSON parsing without serde
    let json = json.trim();

    if !json.starts_with('{') || !json.ends_with('}') {
        return Err(NoiseProtocolError::InvalidPairingCodeMetadata);
    }

    // Checked manually
    #[allow(clippy::string_slice)]
    let inner = &json[1..json.len() - 1];

    let mut salt: Option<String> = None;
    let mut username: Option<String> = None;

    // Split by comma and parse each key-value pair
    for part in inner.split(',') {
        let kv: Vec<&str> = part.splitn(2, ':').collect();
        if kv.len() != 2 {
            continue;
        }

        let key = kv[0].trim().trim_matches('"');
        let value = kv[1].trim().trim_matches('"');

        match key {
            "s" => salt = Some(value.to_string()),
            "u" => username = Some(value.to_string()),
            _ => {}
        }
    }

    match (salt, username) {
        (Some(s), Some(u)) => Ok((s, u)),
        _ => Err(NoiseProtocolError::InvalidPairingCodeMetadata),
    }
}

/// Derive PSK from a pairing code
///
/// Convenience function that decodes the pairing code and derives the PSK.
///
/// # Arguments
/// * `pairing_code` - The combined pairing code string
///
/// # Returns
/// Tuple of (PSK, username)
pub fn derive_psk_from_pairing_code(
    pairing_code: &str,
) -> Result<([u8; PSK_LENGTH], String), NoiseProtocolError> {
    let decoded = decode_pairing_code(pairing_code)?;
    let psk = derive_psk_from_password(&decoded.password, &decoded.salt)?;
    Ok((psk, decoded.username))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_psk_salt().expect("should generate salt");
        let salt2 = generate_psk_salt().expect("should generate salt");

        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        assert_ne!(salt1, salt2); // Should be random
    }

    #[test]
    fn test_derive_psk() {
        let salt = generate_psk_salt().expect("should generate salt");
        let psk = derive_psk_from_password("K7X9", &salt).expect("should derive PSK");

        assert_eq!(psk.len(), PSK_LENGTH);

        // Same password + salt should give same PSK
        let psk2 = derive_psk_from_password("K7X9", &salt).expect("should derive PSK");
        assert_eq!(psk, psk2);

        // Different password should give different PSK
        let psk3 = derive_psk_from_password("A1B2", &salt).expect("should derive PSK");
        assert_ne!(psk, psk3);
    }

    #[test]
    fn test_encode_decode_pairing_code() {
        let salt = generate_psk_salt().expect("should generate salt");
        let password = "K7X9";
        let username = "testuser";

        let pairing_code =
            encode_pairing_code(password, &salt, username).expect("should encode pairing code");

        assert!(pairing_code.starts_with("K7X9:"));

        let decoded = decode_pairing_code(&pairing_code).expect("should decode pairing code");

        assert_eq!(decoded.password, password);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.username, username);
    }

    #[test]
    fn test_derive_psk_from_pairing_code() {
        let salt = generate_psk_salt().expect("should generate salt");
        let password = "K7X9";
        let username = "testuser";

        let pairing_code =
            encode_pairing_code(password, &salt, username).expect("should encode pairing code");

        let (psk, decoded_username) = derive_psk_from_pairing_code(&pairing_code)
            .expect("should derive PSK from pairing code");

        assert_eq!(psk.len(), PSK_LENGTH);
        assert_eq!(decoded_username, username);

        // Should match direct derivation
        let direct_psk = derive_psk_from_password(password, &salt).expect("should derive PSK");
        assert_eq!(psk, direct_psk);
    }

    #[test]
    fn test_invalid_pairing_code() {
        // Missing colon
        assert!(decode_pairing_code("K7X9").is_err());

        // Empty password
        assert!(decode_pairing_code(":eyJzIjoiYWJjIiwidSI6InRlc3QifQ==").is_err());

        // Invalid base64
        assert!(decode_pairing_code("K7X9:not-valid-base64!!!").is_err());

        // Invalid JSON
        assert!(decode_pairing_code("K7X9:bm90anNvbg==").is_err()); // "notjson" in base64
    }
}
