//! Tests for the script launchers, against real files and child processes. The unit tests cover
//! what a fake runner or environment can.
//! They are `#[ignore]`d, as most need `pwsh` on `PATH`; run them with:
//!
//! ```text
//! cargo test -p bitwarden-access-connector --all-features -- --ignored
//! ```

mod common;
use common::*;

/// Mounts a rotation exchange. The poll mock keeps offering the same job; assert with
/// [`assert_outcome`], which ignores the count.
#[allow(clippy::too_many_arguments)]
async fn mount_rotation(
    api: &MockServer,
    org_key: &bitwarden_crypto::SymmetricCryptoKey,
    cipher_json: serde_json::Value,
    job_id: Uuid,
    attempt_id: Uuid,
    target_id: Uuid,
    cipher_id: Uuid,
    terminate_sessions: bool,
) {
    Mock::given(method("GET"))
        .and(path("/access-connectors/rotation/jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [{"jobId": job_id, "targetSystemId": target_id}]
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/access-connectors/rotation/jobs/{job_id}/claim"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(claim_body(
                    org_key,
                    attempt_id,
                    job_id,
                    target_id,
                    cipher_id,
                    terminate_sessions,
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(api)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(cipher_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(api)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/cipher"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/success"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(api)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/access-connectors/rotation/attempts/{attempt_id}/failure"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(api)
        .await;
}

async fn failure_detail(api: &MockServer) -> String {
    let requests = api
        .received_requests()
        .await
        .expect("request recording is on by default");
    let body = requests
        .iter()
        .find(|r| r.url.path().ends_with("/failure"))
        .expect("no failure was reported")
        .body
        .clone();
    String::from_utf8(body).expect("the failure report is utf-8")
}

/// Asserts which outcome the connector reported, ignoring how many rotations it got through.
async fn assert_outcome(api: &MockServer, expect_success: bool) {
    let requests = api
        .received_requests()
        .await
        .expect("request recording is on by default");
    let saw = |suffix: &str| requests.iter().any(|r| r.url.path().ends_with(suffix));

    let (success, failure) = (saw("/success"), saw("/failure"));
    let body_of = |suffix: &str| {
        requests
            .iter()
            .find(|r| r.url.path().ends_with(suffix))
            .map_or_else(
                || "<none>".to_string(),
                |r| String::from_utf8_lossy(&r.body).into_owned(),
            )
    };
    let reports = || {
        format!(
            "failure report: {}; success report: {}",
            body_of("/failure"),
            body_of("/success")
        )
    };
    if expect_success {
        assert!(success, "no success was reported; {}", reports());
        assert!(!failure, "a failure was reported as well; {}", reports());
    } else {
        assert!(failure, "no failure was reported; {}", reports());
        assert!(!success, "a success was reported as well; {}", reports());
    }
}

/// Runs the connector against `api`/`identity` with `vars` set until it reports an outcome or
/// `deadline` passes, then shuts it down. The deadline is generous because PowerShell start-up is
/// slow.
async fn run_access_connector_with_env(
    api: &MockServer,
    identity: &MockServer,
    script_root: Option<std::path::PathBuf>,
    vars: Vec<(String, String)>,
    deadline: Duration,
) {
    {
        let _guard = lock_env();
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            for (k, v) in &vars {
                std::env::set_var(k, v);
            }
        }
    }

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let cfg = make_cfg(api.uri(), identity.uri(), script_root);
    let handle =
        tokio::spawn(async move { bitwarden_access_connector::run(cfg, cancel_clone).await });

    let give_up = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < give_up {
        let requests = api.received_requests().await.expect("recording is on");
        if requests.iter().any(|r| {
            let p = r.url.path();
            p.ends_with("/success") || p.ends_with("/failure")
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cancel.cancel();
    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = lock_env();
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            for (k, _) in &vars {
                std::env::remove_var(k);
            }
        }
    }
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn ps1_is_dispatched_to_a_powershell_host_and_receives_the_payload() {
    // A .ps1 cannot be executed by the kernel, so output at all proves a host interpreted it.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let out = tmp.path().join("payload.json");

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        true,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        vec![
            (
                format!("{prefix}SCRIPT"),
                fixtures_dir()
                    .join("copy_stdin.ps1")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                format!("{prefix}OUT_PATH"),
                out.to_string_lossy().into_owned(),
            ),
        ],
        // Three host start-ups: rotate, verify and terminate.
        Duration::from_millis(30_000),
    )
    .await;

    assert_outcome(&api, true).await;

    let payload_for = |operation: &str| -> serde_json::Value {
        let file = out.with_file_name(format!("payload.json.{operation}"));
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|_| panic!("the host wrote no {operation} payload"));
        serde_json::from_str(&text).expect("payload must be JSON")
    };

    for operation in ["rotate", "verify"] {
        let payload = payload_for(operation);
        assert_eq!(payload["operation"], operation);
        assert_eq!(payload["accountIdentity"], "testuser@example.com");
        assert!(
            payload.get("newPassword").is_some(),
            "the {operation} script must receive the new password: {payload}"
        );
    }

    let terminate = payload_for("terminate");
    assert_eq!(terminate["operation"], "terminate");
    assert_eq!(terminate["accountIdentity"], "testuser@example.com");
    assert!(
        terminate.get("newPassword").is_none(),
        "the terminate script must not receive the new password: {terminate}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn a_transient_exit_code_survives_a_real_powershell_host() {
    // Only a real host shows `exit 4` coming back as the process exit status.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        false,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        vec![
            (
                format!("{prefix}SCRIPT"),
                fixtures_dir()
                    .join("exit_code.ps1")
                    .to_string_lossy()
                    .into_owned(),
            ),
            // Exit 4 is a transient failure that leaves the target untouched.
            (format!("{prefix}EXIT_CODE"), "4".to_string()),
        ],
        // The test config allows two tries, so this needs two host start-ups.
        Duration::from_millis(30_000),
    )
    .await;

    assert_outcome(&api, false).await;

    let requests = api.received_requests().await.expect("requests");
    assert!(
        !requests.iter().any(|r| r.method.as_str() == "PUT"),
        "PUT cipher must NOT be called when rotate fails"
    );

    let body: serde_json::Value =
        serde_json::from_str(&failure_detail(&api).await).expect("failure body is JSON");
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
    // A host that crashed would exit 1 and match the checks above; the detail pins the code itself.
    assert_eq!(
        body["detail"],
        serde_json::json!("exit code 4"),
        "the script's exit code must reach the connector: {body}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn a_failing_terminate_step_is_reported_but_the_rotation_succeeds() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        true,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        vec![(
            format!("{prefix}SCRIPT"),
            fixtures_dir()
                .join("terminate_fail.ps1")
                .to_string_lossy()
                .into_owned(),
        )],
        Duration::from_millis(20_000),
    )
    .await;

    assert_outcome(&api, true).await;

    let requests = api.received_requests().await.expect("requests");
    assert!(
        requests.iter().any(|r| r.method.as_str() == "PUT"),
        "PUT cipher must be called (rotation succeeded even when terminate fails)"
    );

    let success = requests
        .iter()
        .find(|r| r.url.path().ends_with("/success"))
        .expect("success report must be sent even when terminate exits nonzero");
    let body: serde_json::Value =
        serde_json::from_slice(&success.body).expect("success body is JSON");
    assert_eq!(
        body["sessionTermination"],
        serde_json::json!(2),
        "sessionTermination must be 2 (TermFailed) when terminate exits 1: {body}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn the_allowlist_keeps_credentials_out_of_a_real_child_process() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let out = tmp.path().join("env.json");

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        false,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        vec![
            (
                format!("{prefix}SCRIPT"),
                fixtures_dir()
                    .join("dump_env.ps1")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                format!("{prefix}OUT_PATH"),
                out.to_string_lossy().into_owned(),
            ),
            // A per-target credential and the access connector token are both in the connector's
            // environment.
            (
                format!("{prefix}CLIENT_SECRET"),
                "SENTINEL_SECRET_MUST_NOT_LEAK".to_string(),
            ),
            (
                "BWAC_TOKEN".to_string(),
                "SENTINEL_TOKEN_MUST_NOT_LEAK".to_string(),
            ),
        ],
        Duration::from_millis(30_000),
    )
    .await;

    assert_outcome(&api, true).await;

    let dumped = std::fs::read_to_string(&out).expect("the host wrote no environment");
    assert!(
        !dumped.contains("SENTINEL_SECRET_MUST_NOT_LEAK"),
        "target credential reached the child"
    );
    assert!(
        !dumped.contains("SENTINEL_TOKEN_MUST_NOT_LEAK"),
        "access connector token reached the child"
    );
    // Clearing everything would pass the checks above but fail to start a host on Windows.
    let env: serde_json::Value = serde_json::from_str(&dumped).expect("env dump must be JSON");
    assert!(
        env.get("PATH").is_some(),
        "PATH must survive the allowlist: {env}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn a_script_that_never_reads_stdin_is_still_killed() {
    // The stdin write must sit inside the timeout: a script that never drains stdin blocks it once
    // the payload exceeds the pipe buffer.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        false,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        vec![(
            format!("{prefix}SCRIPT"),
            fixtures_dir()
                .join("sleep_no_stdin.ps1")
                .to_string_lossy()
                .into_owned(),
        )]
        .into_iter()
        // ~1 MB clears every platform's pipe buffer. Split because Windows caps an env var at
        // 32,767 characters.
        .chain((0..36).map(|i| (format!("{prefix}BULK_{i:02}"), "x".repeat(30_000))))
        .collect(),
        // The test config's script_timeout is 10s; allow it to fire and be reported.
        Duration::from_millis(20_000),
    )
    .await;

    assert_outcome(&api, false).await;
}

// Unix only: creating a symlink on Windows needs Developer Mode or admin rights.
#[cfg(unix)]
#[tokio::test]
#[ignore = "Integration test resolves real symlinks on disk"]
async fn a_symlink_pointing_outside_script_root_is_rejected() {
    // Containment is `canonicalize` plus `starts_with`; only a real link tests it.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let (target_id, cipher_id) = (Uuid::new_v4(), KEYED_LOGIN_ID);
    let prefix = env_prefix(target_id);

    let root = tempfile::TempDir::new().expect("temp dir");
    let link = root.path().join("escape.sh");
    std::os::unix::fs::symlink("/bin/sh", &link).expect("symlink");

    mount_rotation(
        &api,
        &org_key,
        keyed_login_json(),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
        false,
    )
    .await;

    run_access_connector_with_env(
        &api,
        &identity,
        Some(root.path().to_path_buf()),
        vec![(
            format!("{prefix}SCRIPT"),
            link.to_string_lossy().into_owned(),
        )],
        Duration::from_millis(3000),
    )
    .await;

    assert_outcome(&api, false).await;
    // ScriptNotFound would mean the link was never followed.
    let detail = failure_detail(&api).await;
    assert!(
        detail.contains("ScriptOutsideRoot"),
        "expected the root check to reject it, got: {detail}"
    );
}
