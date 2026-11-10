//! # TEST-ONLY: Access connector registration payload generator
//!
//! WARNING: handles a plaintext organisation key; never use in production. Reads it from
//! `BWAC_ORG_KEY_B64` or stdin, never argv, and prints the payload as JSON to stdout only.
//!
//! ```text
//! export BWAC_ORG_KEY_B64="<base64-encoded-org-key>"
//! cargo run -p bitwarden-access-connector --example register -- --name my-connector
//! ```

// Prints the payload to stdout and operator guidance to stderr.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{self, BufRead};

use bitwarden_access_connector::token::{DERIVE_INFO, DERIVE_NAME};
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeyEncryptable, SymmetricCryptoKey, derive_shareable_key,
    generate_random_bytes,
};
use bitwarden_encoding::B64;
use clap::Parser;
use zeroize::Zeroizing;

/// TEST-ONLY access connector registration payload generator.
///
/// Prints a JSON registration payload and token template to stdout.
/// The organisation key is read from BWAC_ORG_KEY_B64 or stdin, never argv.
#[derive(Parser)]
#[command(
    name = "register",
    about = "TEST-ONLY: generate an access connector registration payload"
)]
struct Cli {
    /// Display name for the connector (sent in the registration request).
    #[arg(long, default_value = "test-connector")]
    name: String,
}

/// A generated registration payload. `Debug` redacts `encryption_key_b64`.
pub struct RegisterPayload {
    /// The connector display name.
    pub name: String,
    /// The `encryptedPayload` field for the register API call.
    pub encrypted_payload: String,
    /// The 16-byte seed's base64, encrypted under the org key.
    pub key: String,
    /// The raw 16-byte seed encoded as base64 (the `:` suffix of the token).
    /// Never log this value.
    pub encryption_key_b64: Zeroizing<String>,
}

impl std::fmt::Debug for RegisterPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterPayload")
            .field("name", &self.name)
            .field("encrypted_payload", &"<EncString>")
            .field("key", &"<EncString>")
            .field("encryption_key_b64", &"[REDACTED]")
            .finish()
    }
}

/// Generate the registration payload for a new access connector. `org_key_b64` must never appear
/// in logs.
///
/// # Errors
///
/// A descriptive string for a malformed or wrong-size org key; never echoes key material.
pub fn generate_registration_payload(
    org_key_b64: &str,
    name: &str,
) -> Result<RegisterPayload, String> {
    let org_key_b64_parsed: B64 = org_key_b64
        .trim()
        .parse()
        .map_err(|_| "org key is not valid base64".to_string())?;

    let org_key_bytes = BitwardenLegacyKeyBytes::from(&org_key_b64_parsed);
    let org_key = SymmetricCryptoKey::try_from(&org_key_bytes)
        .map_err(|_| "org key bytes have the wrong length for a symmetric key".to_string())?;

    let seed: Zeroizing<[u8; 16]> = generate_random_bytes();

    let seed_b64 = B64::from(seed.as_slice());
    let encryption_key_b64 = Zeroizing::new(seed_b64.to_string());

    // Must match AccessConnectorToken::from_str.
    let derived = derive_shareable_key(seed, DERIVE_NAME, Some(DERIVE_INFO));
    let derived_key = SymmetricCryptoKey::Aes256CbcHmacKey(derived);

    // The identity server returns this after authentication; the connector
    // decrypts it (using derived_key) to recover the org key.
    let org_key_b64_str = org_key_b64_parsed.to_string();
    let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);

    let encrypted_payload: EncString = payload_json
        .as_str()
        .encrypt_with_key(&derived_key)
        .map_err(|e| format!("failed to encrypt payload: {e}"))?;

    let key_enc: EncString = encryption_key_b64
        .as_str()
        .encrypt_with_key(&org_key)
        .map_err(|e| format!("failed to encrypt key field: {e}"))?;

    Ok(RegisterPayload {
        name: name.to_string(),
        encrypted_payload: encrypted_payload.to_string(),
        key: key_enc.to_string(),
        encryption_key_b64,
    })
}

fn main() {
    let cli = Cli::parse();

    // The banner goes to stderr, so it stays out of the JSON callers parse from stdout.
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  TEST-ONLY: access connector registration payload generator  ║");
    eprintln!("║  This binary handles a plaintext org key.                    ║");
    eprintln!("║  Do NOT use in production.                                   ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    let org_key_b64 = match std::env::var("BWAC_ORG_KEY_B64") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => {
            eprintln!("BWAC_ORG_KEY_B64 not set — reading org key from stdin (first line):");
            let stdin = io::stdin();
            let mut line = String::new();
            stdin
                .lock()
                .read_line(&mut line)
                .expect("failed to read from stdin");
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                eprintln!("error: no org key provided (empty stdin)");
                std::process::exit(1);
            }
            trimmed
        }
    };

    let payload = match generate_registration_payload(&org_key_b64, &cli.name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    // The register request body, which must never carry the plaintext org key or seed.
    println!(
        "{}",
        serde_json::json!({
            "name": payload.name,
            "encryptedPayload": payload.encrypted_payload,
            "key": payload.key,
        })
    );

    // The seed goes to stdout, never a log, because the operator embeds it in the token.
    println!();
    println!(
        "token template: 0.access-connector.<apiKeyId>.<clientSecret>:{}",
        payload.encryption_key_b64.as_str()
    );
    println!("(substitute <apiKeyId> and <clientSecret> from the register API response)");
}

// Tests kept in the example for discoverability; run via `cargo test --example register`.

#[cfg(test)]
mod tests {
    use bitwarden_access_connector::{
        crypto::{AccessConnectorKeyStore, AccessConnectorSymmSlotId, unwrap_org_key},
        token::AccessConnectorToken,
    };
    use bitwarden_crypto::{KeyDecryptable, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_encoding::B64;

    use super::generate_registration_payload;

    fn make_test_org_key_b64() -> (SymmetricCryptoKey, String) {
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let b64 = B64::from(org_key.to_encoded().as_ref()).to_string();
        (org_key, b64)
    }

    /// Full round-trip: generate payload → parse token → unwrap org key → probe.
    #[test]
    fn register_round_trip() {
        let (org_key, org_key_b64) = make_test_org_key_b64();

        let payload = generate_registration_payload(&org_key_b64, "round-trip-connector")
            .expect("generate_registration_payload should succeed");

        // Placeholder apiKeyId and clientSecret; only the seed suffix feeds the derived key.
        let fake_api_key_id = "00000000-0000-0000-0000-000000000001";
        let fake_client_secret = "testsecret";
        let token_str = format!(
            "0.access-connector.{}.{}:{}",
            fake_api_key_id,
            fake_client_secret,
            payload.encryption_key_b64.as_str()
        );

        // Parsing re-derives the full symmetric key from the seed.
        let token: AccessConnectorToken = token_str
            .parse()
            .expect("synthetic token must parse successfully");

        let store: AccessConnectorKeyStore = KeyStore::default();
        unwrap_org_key(&store, &token.encryption_key, &payload.encrypted_payload)
            .expect("unwrap_org_key must succeed with the correct derived key");

        // Encrypt under the recovered org key and decrypt under the original one.
        let probe = "access-connector-register-round-trip-probe";
        let encrypted_probe = {
            use bitwarden_crypto::PrimitiveEncryptable;
            let mut ctx = store.context_mut();
            probe
                .encrypt(&mut ctx, AccessConnectorSymmSlotId::Organization)
                .expect("encrypt probe under recovered org key")
        };

        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe under original org key");

        assert_eq!(
            decrypted, probe,
            "org key recovered from encryptedPayload must match the original"
        );
    }

    #[test]
    fn bad_org_key_b64_errors() {
        let result = generate_registration_payload("!!!not-base64!!!", "test");
        assert!(result.is_err(), "expected error for invalid base64");
        let msg = result.unwrap_err();
        assert!(
            !msg.contains("!!!"),
            "error message echoed key material: {msg}"
        );
    }

    #[test]
    fn seeds_are_distinct() {
        let (_org_key, org_key_b64) = make_test_org_key_b64();
        let p1 = generate_registration_payload(&org_key_b64, "d1").unwrap();
        let p2 = generate_registration_payload(&org_key_b64, "d2").unwrap();
        assert_ne!(
            p1.encryption_key_b64.as_str(),
            p2.encryption_key_b64.as_str(),
            "two registrations must produce distinct encryption_key seeds"
        );
    }
}
