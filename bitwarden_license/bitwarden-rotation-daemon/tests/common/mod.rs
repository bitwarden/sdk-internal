//! Shared harness for the daemon's integration tests.
//!
//! Stands up wiremock identity and API servers with self-consistent token, payload, and cipher
//! fixtures, so each test file drives the real `bitwarden_rotation_daemon::run` rather than
//! reaching into crate internals.
//!
//! These tests do mutate the real process environment: the daemon resolves per-target
//! credentials from it, and exercising that is the point. Every test that does so takes
//! [`ENV_LOCK`] first.

#![allow(dead_code)]

// Re-exported so each test file gets the harness and the things it drives the harness with
// from a single `use common::*;`.
pub use std::time::Duration;
use std::{path::PathBuf, str::FromStr, sync::Mutex};

use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};
use bitwarden_encoding::B64;
pub use bitwarden_rotation_daemon::executor::RunExit;
use bitwarden_rotation_daemon::{executor::DaemonConfig, token::DaemonToken};
pub use bitwarden_threading::cancellation_token::CancellationToken;
pub use uuid::Uuid;
pub use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

/// Serialises tests that mutate env vars, for safe concurrent mutation.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// The test daemon token (SM test vector, adapted to the 4-part daemon format).
pub const TEST_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

pub fn test_token() -> DaemonToken {
    DaemonToken::from_str(TEST_TOKEN_STR).expect("test token must parse")
}

/// Derive the token's encryption key (mirrors token.rs C1 derivation).
pub fn token_encryption_key() -> SymmetricCryptoKey {
    use bitwarden_crypto::derive_shareable_key;
    let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().expect("valid b64");
    let seed: Zeroizing<[u8; 16]> = Zeroizing::new(b64.as_bytes().try_into().expect("16 bytes"));
    SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
        seed,
        "accesstoken",
        Some("sm-access-token"),
    ))
}

/// Generate a fresh org key and its matching `encryptedPayload` for the
/// identity server response.
pub fn make_org_key_and_payload() -> (SymmetricCryptoKey, String) {
    let token_key = token_encryption_key();
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let org_key_bytes = org_key.to_encoded();
    let org_key_b64_str: String = B64::from(org_key_bytes.as_ref()).into();
    let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);
    let encrypted_payload = payload_json
        .as_str()
        .encrypt_with_key(&token_key)
        .expect("encrypt payload")
        .to_string();
    (org_key, encrypted_payload)
}

/// Mount a permanent identity success mock.
pub async fn mount_identity_ok(server: &MockServer, encrypted_payload: &str) {
    let body = format!(
        r#"{{"access_token":"test-bearer","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
    );
    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .insert_header("content-type", "application/json"),
        )
        .mount(server)
        .await;
}

/// Build a cipher data JSON string (password encrypted under org_key, plus a
/// Username field) — this is what the cipher-read endpoint returns.
pub fn make_cipher_data(org_key: &SymmetricCryptoKey, password: &str) -> String {
    let enc = password
        .encrypt_with_key(org_key)
        .expect("encrypt password")
        .to_string();
    serde_json::json!({ "Password": enc, "Username": "testuser" }).to_string()
}

/// Path to the `tests/fixtures/` directory.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Convert a target_system_id UUID into the env-var prefix used by the
/// daemon's `EnvCredentialResolver`.
pub fn env_prefix(target_id: Uuid) -> String {
    let mut s = target_id.to_string().to_uppercase();
    s = s.replace('-', "_");
    s.push('_');
    s
}

/// Build a minimal fast `DaemonConfig` for integration tests.
pub fn make_cfg(
    api_url: String,
    identity_url: String,
    script_root: Option<PathBuf>,
) -> DaemonConfig {
    DaemonConfig::new_for_test(
        api_url,
        identity_url,
        test_token(),
        Duration::from_millis(50), // fast poll for tests
        script_root,
    )
}

/// An RFC-3339 execute_by timestamp 5 minutes in the future.
pub fn execute_by_future() -> String {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(5))
        .expect("time in range")
        .to_rfc3339()
}

/// Build a claim response body for a CustomScript job.
pub fn claim_body(
    attempt_id: Uuid,
    job_id: Uuid,
    target_id: Uuid,
    cipher_id: Uuid,
    terminate_sessions: bool,
) -> serde_json::Value {
    serde_json::json!({
        "attemptId": attempt_id,
        "jobId": job_id,
        "targetSystemId": target_id,
        "targetSystemName": "test-system",
        "kind": 2,  // CustomScript
        "passwordPolicy": {
            "minLength": 8,
            "maxLength": 128,
            "includeUppercase": true,
            "includeLowercase": true,
            "includeDigits": true,
            "includeSymbols": false
        },
        "cipherId": cipher_id,
        "accountIdentity": "testuser@example.com",
        "terminateSessions": terminate_sessions,
        "executeBy": execute_by_future()
    })
}
