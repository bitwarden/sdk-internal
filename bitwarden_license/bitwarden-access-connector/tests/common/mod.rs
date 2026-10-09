//! Shared harness for the connector's integration tests: wiremock identity and API servers with
//! self-consistent token, payload and cipher fixtures.
//!
//! Tests set per-target credentials in the real process environment, so each takes [`ENV_LOCK`]
//! first.

#![allow(dead_code)]

// Re-exported so each test file needs only `use common::*;`.
pub use std::time::Duration;
use std::{
    path::PathBuf,
    sync::{LazyLock, Mutex},
};

pub use bitwarden_access_connector::executor::RunExit;
use bitwarden_access_connector::{
    crypto::{AccessConnectorKeyStore, AccessConnectorSymmSlotId},
    executor::AccessConnectorConfig,
};
use bitwarden_access_token::{AccessToken, AccessTokenKind, make_access_token_secrets};
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, KeyDecryptable, KeyEncryptable, KeyStore, SymmetricCryptoKey,
    SymmetricKeyAlgorithm,
};
use bitwarden_encoding::B64;
pub use bitwarden_threading::cancellation_token::CancellationToken;
pub use uuid::Uuid;
pub use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Serialises tests that mutate env vars.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A real token and its derived key, minted once via `make_access_token_secrets` so the two
/// always agree.
static TEST_CREDENTIAL: LazyLock<(String, SymmetricCryptoKey)> = LazyLock::new(|| {
    let wrapping_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let store: AccessConnectorKeyStore = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(
            AccessConnectorSymmSlotId::Organization,
            wrapping_key.clone(),
        )
        .expect("set_symmetric_key");

    let secrets = {
        let mut ctx = store.context_mut();
        make_access_token_secrets(
            &mut ctx,
            AccessConnectorSymmSlotId::Organization,
            AccessTokenKind::AccessConnector,
        )
        .expect("mint secrets")
    };

    // Recover the derived key from the `key` field, as an organization would.
    let derived_key_b64: String = secrets
        .key
        .decrypt_with_key(&wrapping_key)
        .expect("decrypt key field");
    let b64: B64 = derived_key_b64.parse().expect("valid b64");
    let derived_key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&b64))
        .expect("valid derived key");

    let token_str = secrets.into_token(Uuid::new_v4(), "test-secret");
    (token_str, derived_key)
});

pub fn test_token() -> AccessToken {
    AccessToken::parse(&TEST_CREDENTIAL.0, AccessTokenKind::AccessConnector)
        .expect("test token must parse")
}

pub fn token_encryption_key() -> SymmetricCryptoKey {
    TEST_CREDENTIAL.1.clone()
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

/// The cipher-read endpoint's `data`: the password encrypted under `org_key`, plus a username.
pub fn make_cipher_data(org_key: &SymmetricCryptoKey, password: &str) -> String {
    let enc = password
        .encrypt_with_key(org_key)
        .expect("encrypt password")
        .to_string();
    serde_json::json!({ "Password": enc, "Username": "testuser" }).to_string()
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Convert a target_system_id UUID into the connector's per-target env-var prefix.
pub fn env_prefix(target_id: Uuid) -> String {
    let mut s = target_id.to_string().to_uppercase();
    s = s.replace('-', "_");
    s.push('_');
    s
}

pub fn make_cfg(
    api_url: String,
    identity_url: String,
    script_root: Option<PathBuf>,
) -> AccessConnectorConfig {
    AccessConnectorConfig::new_for_test(
        api_url,
        identity_url,
        test_token(),
        Duration::from_millis(50), // fast poll for tests
        script_root,
    )
}

pub fn execute_by_future() -> String {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(5))
        .expect("time in range")
        .to_rfc3339()
}

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
