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

use bitwarden_access_connector::crypto::{AccessConnectorKeyStore, AccessConnectorSymmSlotId};
use bitwarden_access_token::{AccessTokenKind, make_access_token_secrets};
use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeyStore, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use clap::Parser;
use uuid::Uuid;

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

/// A generated registration payload. `Debug` redacts `token_template`, which carries the seed.
pub struct RegisterPayload {
    /// The connector display name.
    pub name: String,
    /// The `encryptedPayload` field for the register API call.
    pub encrypted_payload: String,
    /// The derived key's base64, encrypted under the org key.
    pub key: String,
    /// The access token, with `<apiKeyId>` and `<clientSecret>` placeholders for the operator to
    /// fill in from the register API response.
    pub token_template: String,
}

impl std::fmt::Debug for RegisterPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterPayload")
            .field("name", &self.name)
            .field("encrypted_payload", &"<EncString>")
            .field("key", &"<EncString>")
            .field("token_template", &"[REDACTED]")
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

    // Throwaway store so make_access_token_secrets can read the org key.
    let store: AccessConnectorKeyStore = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(AccessConnectorSymmSlotId::Organization, org_key)
        .map_err(|e| format!("failed to install org key: {e}"))?;

    let secrets = {
        let mut ctx = store.context_mut();
        make_access_token_secrets(
            &mut ctx,
            AccessConnectorSymmSlotId::Organization,
            AccessTokenKind::AccessConnector,
        )
        .map_err(|e| format!("failed to mint registration secrets: {e}"))?
    };

    let encrypted_payload = secrets.encrypted_payload.to_string();
    let key = secrets.key.to_string();

    // Build with a nil UUID, then swap it for the `<apiKeyId>` placeholder.
    let placeholder_id = Uuid::nil();
    let token_template = secrets
        .into_token(placeholder_id, "<clientSecret>")
        .replacen(&placeholder_id.to_string(), "<apiKeyId>", 1);

    Ok(RegisterPayload {
        name: name.to_string(),
        encrypted_payload,
        key,
        token_template,
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
    println!("token template: {}", payload.token_template);
    println!("(substitute <apiKeyId> and <clientSecret> from the register API response)");
}

// Tests kept in the example for discoverability; run via `cargo test --example register`.

#[cfg(test)]
mod tests {
    use bitwarden_access_connector::crypto::{AccessConnectorKeyStore, AccessConnectorSymmSlotId};
    use bitwarden_access_token::{AccessToken, AccessTokenKind};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_encoding::B64;

    use super::generate_registration_payload;

    fn make_test_org_key_b64() -> (SymmetricCryptoKey, String) {
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let b64 = B64::from(org_key.to_encoded().as_ref()).to_string();
        (org_key, b64)
    }

    /// Generate payload → fill in the token template → parse → open_payload → probe.
    #[test]
    fn register_round_trip() {
        let (org_key, org_key_b64) = make_test_org_key_b64();

        let payload = generate_registration_payload(&org_key_b64, "round-trip-connector")
            .expect("generate_registration_payload should succeed");

        // Placeholder apiKeyId and clientSecret, as an operator would substitute them.
        let token_str = payload
            .token_template
            .replace("<apiKeyId>", "00000000-0000-0000-0000-000000000001")
            .replace("<clientSecret>", "testsecret");

        // Parsing re-derives the full symmetric key from the seed.
        let token = AccessToken::parse(&token_str, AccessTokenKind::AccessConnector)
            .expect("synthetic token must parse successfully");

        let store: AccessConnectorKeyStore = KeyStore::default();
        token
            .open_payload(
                &mut store.context_mut(),
                &payload.encrypted_payload,
                AccessConnectorSymmSlotId::Organization,
            )
            .expect("open_payload must succeed with the correct derived key");

        let ctx = store.context();
        #[allow(deprecated)]
        let recovered_b64 = ctx
            .dangerous_get_symmetric_key(AccessConnectorSymmSlotId::Organization)
            .expect("the slot was just populated")
            .to_base64();

        assert_eq!(
            recovered_b64.to_string(),
            org_key.to_base64().to_string(),
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
            p1.token_template, p2.token_template,
            "two registrations must produce distinct seeds"
        );
    }
}
