//! Black-box integration tests for the rotation daemon end-to-end flow.
//!
//! Each test starts a wiremock MockServer pretending to be the identity and
//! API servers, then drives `bitwarden_rotation_daemon::run(cfg, cancel)`
//! against them.  The daemon token, encrypted_payload, and cipher fixtures
//! are all internally consistent, generated from the crate's own crypto helpers.
//!
//! # Credential resolution
//!
//! The daemon's env resolver reads env vars with the pattern
//! `{TARGET_ID_UPPER_UNDERSCORE}_<SUFFIX>`.  Each test sets the appropriate
//! vars before starting the daemon and removes them afterward.  Because
//! env mutation is unsafe in multi-threaded programs, each test that mutates
//! the environment acquires a process-wide mutex (ENV_LOCK) before touching
//! any env vars.

use std::{path::PathBuf, str::FromStr, sync::Mutex, time::Duration};

use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};
use bitwarden_encoding::B64;
use bitwarden_rotation_daemon::{
    executor::{DaemonConfig, RunExit},
    token::DaemonToken,
};
use bitwarden_threading::cancellation_token::CancellationToken;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Process-wide env lock for tests that mutate environment variables
// ---------------------------------------------------------------------------

/// Serialise all tests that mutate env vars so that concurrent mutation is safe.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Shared constants and helpers
// ---------------------------------------------------------------------------

/// The test daemon token (SM test vector, adapted to the 4-part daemon format).
const TEST_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

fn test_token() -> DaemonToken {
    DaemonToken::from_str(TEST_TOKEN_STR).expect("test token must parse")
}

/// Derive the token's encryption key (mirrors token.rs C1 derivation).
fn token_encryption_key() -> SymmetricCryptoKey {
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
fn make_org_key_and_payload() -> (SymmetricCryptoKey, String) {
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
async fn mount_identity_ok(server: &MockServer, encrypted_payload: &str) {
    let body = format!(
        r#"{{"access_token":"test-bearer","expires_in":3600,"encryptedPayload":"{encrypted_payload}"}}"#
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
fn make_cipher_data(org_key: &SymmetricCryptoKey, password: &str) -> String {
    let enc = password
        .encrypt_with_key(org_key)
        .expect("encrypt password")
        .to_string();
    serde_json::json!({ "Password": enc, "Username": "testuser" }).to_string()
}

/// Path to the `tests/fixtures/` directory.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Convert a target_system_id UUID into the env-var prefix used by the
/// daemon's `EnvCredentialResolver`.
fn env_prefix(target_id: Uuid) -> String {
    let mut s = target_id.to_string().to_uppercase();
    s = s.replace('-', "_");
    s.push('_');
    s
}

/// Build a minimal fast `DaemonConfig` for integration tests.
fn make_cfg(api_url: String, identity_url: String, script_root: Option<PathBuf>) -> DaemonConfig {
    DaemonConfig::new_for_test(
        api_url,
        identity_url,
        test_token(),
        Duration::from_millis(50), // fast poll for tests
        script_root,
    )
}

/// An RFC-3339 execute_by timestamp 5 minutes in the future.
fn execute_by_future() -> String {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(5))
        .expect("time in range")
        .to_rfc3339()
}

/// Build a claim response body for a CustomScript job.
fn claim_body(
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

// ---------------------------------------------------------------------------
// Scenario 1 — Happy path
// ---------------------------------------------------------------------------
//
// Identity auth succeeds → poll returns one job → claim (CustomScript,
// exit_code.sh with exit 0) → GET cipher → PUT (password re-encrypted under
// org_key) → success report with sessionTermination=0 (NotRequested).
// Then cancel → Shutdown.

#[tokio::test]
async fn happy_path_rotate_and_report_success() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let job_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let cipher_id = Uuid::new_v4();
    let prefix = env_prefix(target_id);

    let script_path = fixtures_dir().join("exit_code.sh");

    // Poll: return one job.
    Mock::given(method("GET"))
        .and(path("/rotation/daemon/jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [{"jobId": job_id, "targetSystemId": target_id}]
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    // Claim: succeed.
    Mock::given(method("POST"))
        .and(path(format!("/rotation/jobs/{job_id}/claim")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(attempt_id, job_id, target_id, cipher_id, false))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    // Cipher read.
    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "cipherId": cipher_id,
                    "data": cipher_data,
                    "key": null,
                    "revisionDate": "2024-01-01T00:00:00Z"
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    // Cipher PUT.
    Mock::given(method("PUT"))
        .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    // Success report.
    Mock::given(method("POST"))
        .and(path(format!("/rotation/attempts/{attempt_id}/success")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    // Set env vars: SCRIPT=exit_code.sh, EXIT_CODE=0.
    let script_key = format!("{prefix}SCRIPT");
    let exit_code_key = format!("{prefix}EXIT_CODE");
    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // SAFETY: protected by ENV_LOCK; no concurrent env mutation.
        unsafe {
            std::env::set_var(&script_key, script_path.to_str().expect("utf8 path"));
            std::env::set_var(&exit_code_key, "0");
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_rotation_daemon::run(cfg, cancel_clone).await });

    // Wait for the success report, then cancel.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    // Cleanup.
    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(&script_key);
            std::env::remove_var(&exit_code_key);
        }
    }

    // Verify PUT was called.
    let all_reqs = api.received_requests().await.expect("requests");
    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(!put_reqs.is_empty(), "PUT cipher must have been called");

    // Verify success report was sent with sessionTermination=0 (NotRequested).
    let success_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.url.path().contains("/success"))
        .collect();
    assert!(
        !success_reqs.is_empty(),
        "success report must have been sent"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&success_reqs[0].body).expect("success body is JSON");
    assert_eq!(
        body["sessionTermination"],
        serde_json::json!(0),
        "sessionTermination must be 0 (NotRequested): {body}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 — Failure budget: exit 4 (transient) exhausts retries
// ---------------------------------------------------------------------------
//
// The rotate script exits 4 (transient) every call.  After max_retry_attempts=2
// (set by new_for_test), a failure report is sent with:
//   errorCode = "script_failed"
//   syncState = 0 (TargetUnchanged — rotate never succeeded)
// No PUT cipher should be sent.

#[tokio::test]
async fn transient_exit_exhausts_retry_budget_and_reports_failure() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let job_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let cipher_id = Uuid::new_v4();
    let prefix = env_prefix(target_id);
    let script_path = fixtures_dir().join("exit_code.sh");

    Mock::given(method("GET"))
        .and(path("/rotation/daemon/jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [{"jobId": job_id, "targetSystemId": target_id}]
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/rotation/jobs/{job_id}/claim")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(attempt_id, job_id, target_id, cipher_id, false))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "cipherId": cipher_id,
                    "data": cipher_data,
                    "key": null,
                    "revisionDate": "2024-01-01T00:00:00Z"
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/rotation/attempts/{attempt_id}/failure")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    let script_key = format!("{prefix}SCRIPT");
    let exit_code_key = format!("{prefix}EXIT_CODE");
    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var(&script_key, script_path.to_str().expect("utf8 path"));
            // Exit 4 = transient failure.
            std::env::set_var(&exit_code_key, "4");
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_rotation_daemon::run(cfg, cancel_clone).await });

    // Wait for failure report, then cancel.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(&script_key);
            std::env::remove_var(&exit_code_key);
        }
    }

    let all_reqs = api.received_requests().await.expect("requests");

    // No PUT cipher — rotation never completed.
    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(
        put_reqs.is_empty(),
        "PUT cipher must NOT be called when rotate fails"
    );

    // Failure report must have been sent.
    let failure_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.url.path().contains("/failure"))
        .collect();
    assert!(
        !failure_reqs.is_empty(),
        "failure report must be sent after retry exhaustion"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&failure_reqs[0].body).expect("failure body is JSON");
    assert_eq!(
        body["errorCode"],
        serde_json::json!("script_failed"),
        "errorCode must be script_failed: {body}"
    );
    // syncState=0 = TargetUnchanged (rotate step failed before touching target).
    assert_eq!(
        body["syncState"],
        serde_json::json!(0),
        "syncState must be 0 (TargetUnchanged) when rotate exits 4: {body}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3 — Claim race: 409 on claim → no error, keeps polling
// ---------------------------------------------------------------------------
//
// The claim endpoint always returns 409.  The daemon must keep polling without
// sending any report.  After cancel it exits Shutdown.

#[tokio::test]
async fn claim_race_409_does_not_error_keeps_polling() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    let (_org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let job_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path("/rotation/daemon/jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [{"jobId": job_id, "targetSystemId": target_id}]
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    // Claim always 409.
    Mock::given(method("POST"))
        .and(path(format!("/rotation/jobs/{job_id}/claim")))
        .respond_with(ResponseTemplate::new(409))
        .mount(&api)
        .await;

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_rotation_daemon::run(cfg, cancel_clone).await });

    // Let it poll a few times, then cancel.
    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown, "should exit Shutdown after cancel");

    // No report sent, no cipher PUT.
    let all_reqs = api.received_requests().await.expect("requests");
    let report_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.url.path().contains("/success") || r.url.path().contains("/failure"))
        .collect();
    assert!(
        report_reqs.is_empty(),
        "no report must be sent for a 409 claim race: found {report_reqs:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4 — Credential refused at startup
// ---------------------------------------------------------------------------
//
// Identity returns invalid_client on POST /connect/token.
// run() must return CredentialRefused immediately with no API calls made.

#[tokio::test]
async fn invalid_client_at_startup_returns_credential_refused() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string(r#"{"error":"invalid_client"}"#)
                .insert_header("content-type", "application/json"),
        )
        .mount(&identity)
        .await;

    let cancel = CancellationToken::new();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let exit = bitwarden_rotation_daemon::run(cfg, cancel).await;
    assert_eq!(
        exit,
        RunExit::CredentialRefused,
        "invalid_client must yield CredentialRefused"
    );

    // No API calls at all.
    let api_reqs = api.received_requests().await.expect("requests");
    assert!(
        api_reqs.is_empty(),
        "no API calls should be made when identity rejects at startup: {api_reqs:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5 — terminate_sessions=true, terminate script exits nonzero
// ---------------------------------------------------------------------------
//
// The rotate and verify steps succeed (exit 0), but the terminate step exits 1.
// The success report must have sessionTermination=2 (TermFailed).
// The cipher PUT must still be called (rotation succeeded despite term failure).
//
// Implementation: we write a temporary script that checks argv[1] (the
// operation name) and exits 1 for "terminate", 0 for everything else.

#[tokio::test]
async fn terminate_sessions_nonzero_reports_term_failed_rotation_succeeds() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let job_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let cipher_id = Uuid::new_v4();
    let prefix = env_prefix(target_id);

    // Write a temporary script: exit 1 for terminate, 0 otherwise.
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let wrapper_path = tmpdir.path().join("terminate_fail.sh");
    std::fs::write(
        &wrapper_path,
        b"#!/bin/sh\nop=\"$1\"\nif [ \"$op\" = \"terminate\" ]; then exit 1; fi\ncat > /dev/null\nexit 0\n",
    )
    .expect("write wrapper script");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&wrapper_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&wrapper_path, perms).expect("chmod");
    }

    Mock::given(method("GET"))
        .and(path("/rotation/daemon/jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [{"jobId": job_id, "targetSystemId": target_id}]
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/rotation/jobs/{job_id}/claim")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(
                    attempt_id, job_id, target_id, cipher_id,
                    true, // terminate_sessions = true
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "cipherId": cipher_id,
                    "data": cipher_data,
                    "key": null,
                    "revisionDate": "2024-01-01T00:00:00Z"
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/rotation/attempts/{attempt_id}/success")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    let script_key = format!("{prefix}SCRIPT");
    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var(&script_key, wrapper_path.to_str().expect("utf8 path"));
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_rotation_daemon::run(cfg, cancel_clone).await });

    tokio::time::sleep(Duration::from_millis(4000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(&script_key);
        }
    }

    let all_reqs = api.received_requests().await.expect("requests");

    // PUT cipher must have been called (rotation succeeded).
    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(
        !put_reqs.is_empty(),
        "PUT cipher must be called (rotation succeeded even when terminate fails)"
    );

    // Success report must be sent with sessionTermination=2 (TermFailed).
    let success_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.url.path().contains("/success"))
        .collect();
    assert!(
        !success_reqs.is_empty(),
        "success report must be sent even when terminate exits nonzero"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&success_reqs[0].body).expect("success body is JSON");
    assert_eq!(
        body["sessionTermination"],
        serde_json::json!(2),
        "sessionTermination must be 2 (TermFailed) when terminate exits 1: {body}"
    );
}
