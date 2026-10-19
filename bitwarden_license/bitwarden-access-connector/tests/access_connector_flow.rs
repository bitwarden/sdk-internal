//! Black-box integration tests for the access connector end-to-end flow, run against wiremock
//! identity and API servers.

mod common;
use common::*;

#[cfg(unix)]
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

    Mock::given(method("GET"))
        .and(path("/access-connectors/rotation/jobs"))
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
        .and(path(format!(
            "/access-connectors/rotation/jobs/{job_id}/claim"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(
                    &org_key, attempt_id, job_id, target_id, cipher_id, false,
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
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
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/success"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    let script_key = format!("{prefix}SCRIPT");
    let exit_code_key = format!("{prefix}EXIT_CODE");
    {
        let _guard = lock_env();
        // SAFETY: protected by the env lock; no concurrent env mutation.
        unsafe {
            std::env::set_var(&script_key, script_path.to_str().expect("utf8 path"));
            std::env::set_var(&exit_code_key, "0");
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_access_connector::run(cfg, cancel_clone).await });

    // Wait for the success report, then cancel.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = lock_env();
        unsafe {
            std::env::remove_var(&script_key);
            std::env::remove_var(&exit_code_key);
        }
    }

    let all_reqs = api.received_requests().await.expect("requests");
    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(!put_reqs.is_empty(), "PUT cipher must have been called");

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

#[cfg(unix)]
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
        .and(path("/access-connectors/rotation/jobs"))
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
        .and(path(format!(
            "/access-connectors/rotation/jobs/{job_id}/claim"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(
                    &org_key, attempt_id, job_id, target_id, cipher_id, false,
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
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
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/failure"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    let script_key = format!("{prefix}SCRIPT");
    let exit_code_key = format!("{prefix}EXIT_CODE");
    {
        let _guard = lock_env();
        unsafe {
            std::env::set_var(&script_key, script_path.to_str().expect("utf8 path"));
            // Exit 4 is a transient failure that leaves the target untouched.
            std::env::set_var(&exit_code_key, "4");
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_access_connector::run(cfg, cancel_clone).await });

    // Wait for failure report, then cancel.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = lock_env();
        unsafe {
            std::env::remove_var(&script_key);
            std::env::remove_var(&exit_code_key);
        }
    }

    let all_reqs = api.received_requests().await.expect("requests");

    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(
        put_reqs.is_empty(),
        "PUT cipher must NOT be called when rotate fails"
    );

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
    assert_eq!(
        body["syncState"],
        serde_json::json!(0),
        "syncState must be 0 (TargetUnchanged) when rotate exits 4: {body}"
    );
}

#[tokio::test]
async fn claim_race_409_does_not_error_keeps_polling() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    let (_org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let job_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path("/access-connectors/rotation/jobs"))
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
        .and(path(format!(
            "/access-connectors/rotation/jobs/{job_id}/claim"
        )))
        .respond_with(ResponseTemplate::new(409))
        .mount(&api)
        .await;

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_access_connector::run(cfg, cancel_clone).await });

    // Wait until the connector has attempted the claim at least twice, i.e. it kept polling after
    // losing the race.
    let claim_path = format!("/access-connectors/rotation/jobs/{job_id}/claim");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let claims = api
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|r| r.url.path() == claim_path)
            .count();
        if claims >= 2 || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown, "should exit Shutdown after cancel");

    let all_reqs = api.received_requests().await.expect("requests");
    let claim_attempts = all_reqs
        .iter()
        .filter(|r| r.url.path() == claim_path)
        .count();
    assert!(
        claim_attempts >= 2,
        "connector must keep claiming after a lost race, saw {claim_attempts} claim attempts"
    );
    let report_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.url.path().contains("/success") || r.url.path().contains("/failure"))
        .collect();
    assert!(
        report_reqs.is_empty(),
        "no report must be sent for a 409 claim race: found {report_reqs:?}"
    );
}

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

    let exit = bitwarden_access_connector::run(cfg, cancel).await;
    assert_eq!(
        exit,
        RunExit::CredentialRefused,
        "invalid_client must yield CredentialRefused"
    );

    let api_reqs = api.received_requests().await.expect("requests");
    assert!(
        api_reqs.is_empty(),
        "no API calls should be made when identity rejects at startup: {api_reqs:?}"
    );
}

/// Takes ~3s: `SessionManager::new` makes three attempts with 1s and 2s backoff between them.
#[tokio::test]
async fn transient_identity_failure_at_startup_returns_startup_failed() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&identity)
        .await;

    let cancel = CancellationToken::new();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let exit = bitwarden_access_connector::run(cfg, cancel).await;
    assert_eq!(
        exit,
        RunExit::StartupFailed,
        "a 5xx from identity at startup must yield StartupFailed, not CredentialRefused"
    );

    let api_reqs = api.received_requests().await.expect("requests");
    assert!(
        api_reqs.is_empty(),
        "no API calls should be made when startup authentication fails: {api_reqs:?}"
    );
}

#[cfg(unix)]
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

    // Script exits 1 for terminate, 0 for every other operation.
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let wrapper_path = tmpdir.path().join("terminate_fail.sh");
    std::fs::write(
        &wrapper_path,
        b"#!/bin/sh\nop=\"$1\"\nif [ \"$op\" = \"terminate\" ]; then exit 1; fi\ncat > /dev/null\nexit 0\n",
    )
    .expect("write wrapper script");

    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&wrapper_path)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&wrapper_path, perms).expect("chmod");

    Mock::given(method("GET"))
        .and(path("/access-connectors/rotation/jobs"))
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
        .and(path(format!(
            "/access-connectors/rotation/jobs/{job_id}/claim"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(
                    &org_key, attempt_id, job_id, target_id, cipher_id,
                    true, // terminate_sessions = true
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(&api)
        .await;

    let cipher_data = make_cipher_data(&org_key, "old-password");
    Mock::given(method("GET"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
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
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/success"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;

    let script_key = format!("{prefix}SCRIPT");
    {
        let _guard = lock_env();
        unsafe {
            std::env::set_var(&script_key, wrapper_path.to_str().expect("utf8 path"));
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), None);

    let handle =
        tokio::spawn(async move { bitwarden_access_connector::run(cfg, cancel_clone).await });

    tokio::time::sleep(Duration::from_millis(4000)).await;
    cancel.cancel();

    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = lock_env();
        unsafe {
            std::env::remove_var(&script_key);
        }
    }

    let all_reqs = api.received_requests().await.expect("requests");

    let put_reqs: Vec<_> = all_reqs
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect();
    assert!(
        !put_reqs.is_empty(),
        "PUT cipher must be called (rotation succeeded even when terminate fails)"
    );

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
