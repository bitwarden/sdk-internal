//! # TEST-ONLY: Daemon registration payload generator
//!
//! **WARNING — TEST-ONLY tool. This binary handles a plaintext organisation key
//! and is intended solely for local end-to-end testing before the web-client
//! registration UI exists. Never use it in production.**
//!
//! ## What it does
//!
//! Emulates the ADMIN-side wrap that the web client will eventually perform when
//! registering a new rotation daemon. It:
//!
//! 1. Reads the organisation key from `BWRD_ORG_KEY_B64` or stdin (never argv — command-line
//!    arguments are visible in process listings).
//! 2. Generates a fresh random 16-byte `encryption_key` seed.
//! 3. Derives the full symmetric key via the C1 constants (same derivation as the daemon token
//!    parser — `DERIVE_NAME` / `DERIVE_INFO`).
//! 4. Builds `encryptedPayload` — `{"encryptionKey":"<org-key-b64>"}` encrypted under the derived
//!    key (mirrors the identity-server's auth response).
//! 5. Builds `key` (CONTRACT C4) — the raw 16-byte seed's base64 string, encrypted under the
//!    organisation key as an EncString.  The server stores this opaquely alongside the daemon
//!    registration.
//! 6. Prints a JSON object to **stdout only** (`name`, `encryptedPayload`, `key`) ready to paste
//!    into the register API call, plus a `token template` line showing where the operator must
//!    substitute the API-response values.
//!
//! The organisation key and the generated `encryption_key` seed are **never**
//! written to any log or trace output.
//!
//! ## Usage
//!
//! ```text
//! # Set the org key in the environment:
//! export BWRD_ORG_KEY_B64="<base64-encoded-org-key>"
//! cargo run -p bitwarden-rotation-daemon --example register -- --name my-daemon
//!
//! # Or pipe the key from stdin:
//! echo "<base64-encoded-org-key>" | \
//!   cargo run -p bitwarden-rotation-daemon --example register -- --name my-daemon
//! ```

// This is a CLI tool whose entire purpose is to emit the registration payload to stdout and
// operator guidance to stderr, so print macros are expected here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{self, BufRead};

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeyEncryptable, SymmetricCryptoKey, derive_shareable_key,
    generate_random_bytes,
};
use bitwarden_encoding::B64;
use bitwarden_rotation_daemon::token::{DERIVE_INFO, DERIVE_NAME};
use clap::Parser;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// TEST-ONLY daemon registration payload generator.
///
/// Prints a JSON registration payload and token template to stdout.
/// The organisation key is read from BWRD_ORG_KEY_B64 or stdin — never argv.
#[derive(Parser)]
#[command(
    name = "register",
    about = "TEST-ONLY: generate a daemon registration payload"
)]
struct Cli {
    /// Display name for the daemon (sent in the registration request).
    #[arg(long, default_value = "test-daemon")]
    name: String,
}

// ---------------------------------------------------------------------------
// Core logic (pure function, tested independently)
// ---------------------------------------------------------------------------

/// The output of a successful registration payload generation.
///
/// `Debug` is manually implemented so that `encryption_key_b64` — the raw seed
/// that forms the `:` suffix of the daemon token — is never emitted in debug
/// output.
pub struct RegisterPayload {
    /// The daemon display name.
    pub name: String,
    /// The `encryptedPayload` field for the register API call.
    pub encrypted_payload: String,
    /// CONTRACT C4: the 16-byte seed b64, encrypted under the org key.
    pub key: String,
    /// The raw 16-byte seed encoded as base64 (the `:` suffix of the token).
    /// Never log this value.
    pub encryption_key_b64: Zeroizing<String>,
}

// Manual Debug — redacts the encryption_key_b64 to prevent accidental logging.
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

/// Generate the registration payload for a new rotation daemon.
///
/// # Parameters
///
/// - `org_key_b64`: the organisation's symmetric key encoded as standard base64. This is the
///   crown-jewel key — it must never appear in logs.
/// - `name`: the daemon display name.
///
/// # Errors
///
/// Returns a descriptive error string when the org key cannot be decoded or is
/// the wrong size.  Error messages never echo the key material.
pub fn generate_registration_payload(
    org_key_b64: &str,
    name: &str,
) -> Result<RegisterPayload, String> {
    // --- Parse the org key ---
    let org_key_b64_parsed: B64 = org_key_b64
        .trim()
        .parse()
        .map_err(|_| "org key is not valid base64".to_string())?;

    let org_key_bytes = BitwardenLegacyKeyBytes::from(&org_key_b64_parsed);
    let org_key = SymmetricCryptoKey::try_from(&org_key_bytes)
        .map_err(|_| "org key bytes have the wrong length for a symmetric key".to_string())?;

    // --- Generate the 16-byte encryption_key seed ---
    let seed: Zeroizing<[u8; 16]> = generate_random_bytes();

    // Encode the raw seed to base64 — this is the `:` suffix of the daemon token.
    let seed_b64 = B64::from(seed.as_slice());
    let encryption_key_b64 = Zeroizing::new(seed_b64.to_string());

    // --- Derive the full symmetric key (C1 constants) ---
    // This mirrors DaemonToken::from_str's derivation exactly.
    let derived = derive_shareable_key(seed, DERIVE_NAME, Some(DERIVE_INFO));
    let derived_key = SymmetricCryptoKey::Aes256CbcHmacKey(derived);

    // --- Build encryptedPayload ---
    // The identity server returns this to the daemon after authentication.
    // The daemon decrypts it (using derived_key) to recover the org key.
    let org_key_b64_str = org_key_b64_parsed.to_string();
    let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);

    let encrypted_payload: EncString = payload_json
        .as_str()
        .encrypt_with_key(&derived_key)
        .map_err(|e| format!("failed to encrypt payload: {e}"))?;

    // --- Build key (CONTRACT C4) ---
    // The 16-byte seed's base64 string, encrypted under the org key.
    // Parallel to SM's AccessTokenCreateRequestModel.Key semantics.
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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Print the TEST-ONLY banner to stderr so it doesn't pollute the JSON
    // output that callers parse from stdout.
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  TEST-ONLY: daemon registration payload generator        ║");
    eprintln!("║  This binary handles a plaintext org key.                ║");
    eprintln!("║  Do NOT use in production.                               ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    // Read the org key from the environment or stdin (never argv).
    let org_key_b64 = match std::env::var("BWRD_ORG_KEY_B64") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => {
            eprintln!("BWRD_ORG_KEY_B64 not set — reading org key from stdin (first line):");
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

    // Print the registration JSON to stdout only.
    // The org key and encryption_key are never included here.
    println!(
        "{}",
        serde_json::json!({
            "name": payload.name,
            "encryptedPayload": payload.encrypted_payload,
            "key": payload.key,
        })
    );

    // Print the token template so the operator knows how to assemble the
    // daemon token after they receive the apiKeyId and clientSecret from the
    // register response.
    //
    // The encryption_key_b64 IS printed here because the operator must embed
    // it in the token string — but it goes to stdout only, not logs.
    println!();
    println!(
        "token template: 0.daemon.<apiKeyId>.<clientSecret>:{}",
        payload.encryption_key_b64.as_str()
    );
    println!("(substitute <apiKeyId> and <clientSecret> from the register API response)");
}

// ---------------------------------------------------------------------------
// Tests (kept in the example for discoverability; run via `cargo test --example register`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyDecryptable, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_encoding::B64;
    use bitwarden_rotation_daemon::{
        crypto::{DaemonKeyStore, DaemonSymmSlotId, unwrap_org_key},
        token::DaemonToken,
    };

    use super::generate_registration_payload;

    fn make_test_org_key_b64() -> (SymmetricCryptoKey, String) {
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let b64 = B64::from(org_key.to_encoded().as_ref()).to_string();
        (org_key, b64)
    }

    /// Full round-trip: generate payload → parse token → unwrap org key → probe.
    ///
    /// This exercises both the registration helper and the daemon's key-unwrap
    /// path end-to-end using a synthetic token.
    #[test]
    fn register_round_trip() {
        let (org_key, org_key_b64) = make_test_org_key_b64();

        let payload = generate_registration_payload(&org_key_b64, "round-trip-daemon")
            .expect("generate_registration_payload should succeed");

        // Assemble a synthetic token string (apiKeyId and clientSecret are
        // arbitrary for this test — the token parser only cares about the
        // encryption_key_b64 suffix).
        let fake_api_key_id = "00000000-0000-0000-0000-000000000001";
        let fake_client_secret = "testsecret";
        let token_str = format!(
            "0.daemon.{}.{}:{}",
            fake_api_key_id,
            fake_client_secret,
            payload.encryption_key_b64.as_str()
        );

        // Parse the token — this re-derives the full symmetric key from the seed.
        let token: DaemonToken = token_str
            .parse()
            .expect("synthetic token must parse successfully");

        // Unwrap the org key from encryptedPayload using the token's derived key.
        let store: DaemonKeyStore = KeyStore::default();
        unwrap_org_key(&store, &token.encryption_key, &payload.encrypted_payload)
            .expect("unwrap_org_key must succeed with the correct derived key");

        // Verify the recovered org key encrypts/decrypts a probe correctly.
        let probe = "rotation-daemon-register-round-trip-probe";
        let encrypted_probe = {
            use bitwarden_crypto::PrimitiveEncryptable;
            let mut ctx = store.context_mut();
            probe
                .encrypt(&mut ctx, DaemonSymmSlotId::Organization)
                .expect("encrypt probe under recovered org key")
        };

        // Decrypt using the original org_key to confirm they are the same.
        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe under original org key");

        assert_eq!(
            decrypted, probe,
            "org key recovered from encryptedPayload must match the original"
        );
    }

    /// Confirm a bad org key b64 yields a friendly error.
    #[test]
    fn bad_org_key_b64_errors() {
        let result = generate_registration_payload("!!!not-base64!!!", "test");
        assert!(result.is_err(), "expected error for invalid base64");
        let msg = result.unwrap_err();
        // Must not echo the key material.
        assert!(
            !msg.contains("!!!"),
            "error message echoed key material: {msg}"
        );
    }

    /// Confirm generating two payloads produces different encryption_key seeds.
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
