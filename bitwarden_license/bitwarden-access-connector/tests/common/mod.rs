//! Shared harness: wiremock identity and API servers with self-consistent token, payload and cipher
//! fixtures.
//!
//! Tests mutate per-target env vars, so each takes [`lock_env`] first.

#![allow(dead_code)]

// Re-exported so each test file needs only `use common::*;`.
pub use std::time::Duration;
use std::{
    path::PathBuf,
    sync::{LazyLock, Mutex},
};

use bitwarden_access_connector::executor::AccessConnectorConfig;
pub use bitwarden_access_connector::executor::RunExit;
use bitwarden_access_token::{AccessToken, AccessTokenKind, make_access_token_secrets};
use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, Decryptable, EncString, KeyDecryptable, KeyEncryptable, KeyStore,
    SymmetricCryptoKey, SymmetricKeyAlgorithm,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_pam_sealed::{
    RotationConfigSealedV1, Sealed, SealedPasswordPolicy, SealedTargetSystemKind,
    SealedTargetSystemMethod, TargetSystemSealedV1, seal_rotation_config, seal_target_system,
};
pub use bitwarden_threading::cancellation_token::CancellationToken;
pub use uuid::Uuid;
pub use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Serialises tests that mutate env vars.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Takes [`ENV_LOCK`], ignoring poison so one panicking test doesn't fail the rest.
pub fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A real token and its derived key, minted via `make_access_token_secrets` so they agree.
static TEST_CREDENTIAL: LazyLock<(String, SymmetricCryptoKey)> = LazyLock::new(|| {
    let wrapping_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(test_org_slot(), wrapping_key.clone())
        .expect("set_symmetric_key");

    let secrets = {
        let mut ctx = store.context_mut();
        make_access_token_secrets(&mut ctx, test_org_slot(), AccessTokenKind::AccessConnector)
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

/// The org key the cipher vectors in `tests/fixtures/ciphers` are encrypted under (base64 of the
/// encoded `SymmetricCryptoKey`).
const ORG_KEY_B64: &str =
    "a4oGKmzuPXlJr6ANfFLy9DHw7lmaCo47mc01fROBKMUklVouVlwvgGsX1Sz9D9JHKbqOku/K25akClXWyp8a4g==";

/// The id of the `keyed_login` vector.
pub const KEYED_LOGIN_ID: Uuid = uuid::uuid!("8e1f3a2b-5c4d-4e6f-9a7b-0c1d2e3f4a5b");

pub fn fixture_org_key() -> SymmetricCryptoKey {
    SymmetricCryptoKey::try_from(B64::try_from(ORG_KEY_B64).expect("valid b64"))
        .expect("valid org key")
}

/// [`fixture_org_key`] and its matching `encryptedPayload` for the identity response.
pub fn org_key_and_payload() -> (SymmetricCryptoKey, String) {
    let token_key = token_encryption_key();
    let org_key = fixture_org_key();
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

/// The organisation the harness authenticates into.
pub fn test_org_id() -> OrganizationId {
    "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
        .parse()
        .expect("valid uuid")
}

/// The org slot for [`test_org_id`].
pub fn test_org_slot() -> SymmetricKeySlotId {
    SymmetricKeySlotId::Organization(test_org_id())
}

/// An access token carrying the `organization` claim the connector reads. Mirrors
/// `src/test_support.rs`, which integration tests cannot reach.
pub fn access_token_for(organization_id: OrganizationId) -> String {
    let claims = serde_json::json!({
        "exp": 1_900_000_000u64,
        "sub": "access-connector",
        "scope": ["api.pam.rotation"],
        "organization": organization_id.to_string(),
    });

    let payload = B64Url::from(claims.to_string().as_bytes());
    format!("header.{payload}.signature")
}

pub async fn mount_identity_ok(server: &MockServer, encrypted_payload: &str) {
    let access_token = access_token_for(test_org_id());
    let body = format!(
        r#"{{"access_token":"{access_token}","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
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

/// The cipher-read body: the recorded login cipher with its own item key, password
/// `old-password`, encrypted under [`fixture_org_key`] (see `tests/fixtures/ciphers`).
pub fn keyed_login_json() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/ciphers/keyed_login.json"))
        .expect("vector is JSON")
}

/// Asserts a cipher write `body` rotated the password away from `old_password`, with the old one
/// heading the history. The write's `key` must be exactly `original_key` (the GET's), and the
/// fields must decrypt under the item key unwrapped from it.
pub fn assert_cipher_write_rotated(
    org_key: &SymmetricCryptoKey,
    body: &serde_json::Value,
    original_key: &str,
    old_password: &str,
) {
    assert_eq!(body["key"], original_key, "item key is sent back unchanged");
    // The body is the real request type, not just JSON that happens to decrypt.
    serde_json::from_value::<CipherRequestModel>(body.clone())
        .expect("body is a CipherRequestModel");
    let store = KeyStore::<KeySlotIds>::default();
    let mut ctx = store.context_mut();
    #[allow(deprecated)]
    ctx.set_symmetric_key(test_org_slot(), org_key.clone())
        .expect("set_symmetric_key");

    let wrapped: EncString = original_key.parse().expect("parse");
    let item_key = ctx
        .unwrap_symmetric_key(test_org_slot(), &wrapped)
        .expect("item key unwraps under the org key");
    let mut read = |pointer: &str| -> String {
        let enc: EncString = body
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("no string at {pointer}"))
            .parse()
            .expect("parse");
        enc.decrypt(&mut ctx, item_key).expect("decrypt")
    };

    assert_ne!(read("/login/password"), old_password);
    assert_eq!(read("/passwordHistory/0/password"), old_password);
    assert!(body["login"]["passwordRevisionDate"].is_string());
    assert_eq!(body["lastKnownRevisionDate"], "2024-06-01T12:00:00Z");
    assert!(body["data"].is_null());
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

/// Seal a well-formed target-system and rotation-config pair under `org_key`.
pub fn seal_claim_blobs(
    org_key: &SymmetricCryptoKey,
    target_id: Uuid,
    cipher_id: Uuid,
    terminate_sessions: bool,
) -> (Sealed, Sealed) {
    let store = KeyStore::<KeySlotIds>::default();
    let mut ctx = store.context_mut();
    #[allow(deprecated)]
    ctx.set_symmetric_key(test_org_slot(), org_key.clone())
        .expect("set_symmetric_key");

    let target = TargetSystemSealedV1 {
        target_system_id: target_id,
        method: SealedTargetSystemMethod::Automatic,
        kind: Some(SealedTargetSystemKind::CustomScript),
        password_policy: SealedPasswordPolicy {
            min_length: 8,
            max_length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        },
        supports_session_termination: Some(true),
    };
    let config = RotationConfigSealedV1 {
        target_system_id: target_id,
        cipher_id,
        account_identity: "testuser@example.com".to_owned(),
        terminate_sessions,
    };

    let target_blob = seal_target_system(target, &test_org_slot(), &mut ctx).expect("seal target");
    let config_blob =
        seal_rotation_config(config, &test_org_slot(), &mut ctx).expect("seal config");

    (target_blob, config_blob)
}

pub fn claim_body(
    org_key: &SymmetricCryptoKey,
    attempt_id: Uuid,
    job_id: Uuid,
    target_id: Uuid,
    cipher_id: Uuid,
    terminate_sessions: bool,
) -> serde_json::Value {
    let (target_blob, config_blob) =
        seal_claim_blobs(org_key, target_id, cipher_id, terminate_sessions);

    serde_json::json!({
        "attemptId": attempt_id,
        "jobId": job_id,
        "targetSystemId": target_id,
        "targetSystemName": "test-system",
        "targetSystemSealedData": target_blob.envelope.to_string(),
        "targetSystemWrappedKey": target_blob.wrapped_key.to_string(),
        "cipherId": cipher_id,
        "rotationConfigSealedData": config_blob.envelope.to_string(),
        "rotationConfigWrappedKey": config_blob.wrapped_key.to_string(),
        "executeBy": execute_by_future()
    })
}
