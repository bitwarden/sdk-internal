//! End-to-end tests for the script launchers, against real files and real child processes. The
//! crate's unit tests cover everything a fake runner or environment can.
//!
//! They are `#[ignore]`d, as most need `pwsh` on `PATH`; run them with:
//!
//! ```text
//! cargo test -p bitwarden-access-connector --all-features -- --ignored
//! ```

mod common;
use common::*;

/// Mounts a full rotation exchange. The poll mock keeps offering the same job, so the connector
/// rotates repeatedly; assert through [`assert_outcome`], which ignores the count.
async fn mount_rotation(
    api: &MockServer,
    cipher_data: String,
    job_id: Uuid,
    attempt_id: Uuid,
    target_id: Uuid,
    cipher_id: Uuid,
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
                .set_body_json(claim_body(attempt_id, job_id, target_id, cipher_id, false))
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
                .set_body_json(serde_json::json!({
                    "cipherId": cipher_id,
                    "data": cipher_data,
                    "key": null,
                    "revisionDate": "2024-01-01T00:00:00Z"
                }))
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
    if expect_success {
        assert!(success, "no success was reported");
        assert!(!failure, "a failure was reported as well");
    } else {
        assert!(failure, "no failure was reported");
        assert!(!success, "a success was reported as well");
    }
}

/// Runs the connector against `api`/`identity` for `settle`, with `vars` in the environment, then
/// shuts it down cleanly.
async fn run_access_connector_with_env(
    api: &MockServer,
    identity: &MockServer,
    script_root: Option<std::path::PathBuf>,
    vars: Vec<(String, String)>,
    settle: Duration,
) {
    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // SAFETY: protected by ENV_LOCK; no concurrent env mutation.
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

    tokio::time::sleep(settle).await;
    cancel.cancel();
    let exit = handle.await.expect("task panicked");
    assert_eq!(exit, RunExit::Shutdown);

    {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // SAFETY: protected by ENV_LOCK.
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
    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (target_id, cipher_id) = (Uuid::new_v4(), Uuid::new_v4());
    let prefix = env_prefix(target_id);

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let out = tmp.path().join("payload.json");

    mount_rotation(
        &api,
        make_cipher_data(&org_key, "old-password"),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
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
        Duration::from_millis(4000),
    )
    .await;

    assert_outcome(&api, true).await;

    let payload: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("the host wrote no payload"))
            .expect("payload must be JSON");
    assert_eq!(payload["accountIdentity"], "testuser@example.com");
    assert!(
        payload.get("newPassword").is_some(),
        "the script must receive the new password: {payload}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn the_allowlist_keeps_credentials_out_of_a_real_child_process() {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (target_id, cipher_id) = (Uuid::new_v4(), Uuid::new_v4());
    let prefix = env_prefix(target_id);

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let out = tmp.path().join("env.json");

    mount_rotation(
        &api,
        make_cipher_data(&org_key, "old-password"),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
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
            // A per-target credential and the access connector token, both in the connector's own
            // environment at this point.
            (
                format!("{prefix}CLIENT_SECRET"),
                "SENTINEL_SECRET_MUST_NOT_LEAK".to_string(),
            ),
            (
                "BWAC_TOKEN".to_string(),
                "SENTINEL_TOKEN_MUST_NOT_LEAK".to_string(),
            ),
        ],
        Duration::from_millis(4000),
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
    // A launcher that cleared everything would pass the two checks above, then fail to start a
    // host on Windows.
    let env: serde_json::Value = serde_json::from_str(&dumped).expect("env dump must be JSON");
    assert!(
        env.get("PATH").is_some(),
        "PATH must survive the allowlist: {env}"
    );
}

#[tokio::test]
#[ignore = "Integration test requires PowerShell (pwsh) on PATH"]
async fn a_script_that_never_reads_stdin_is_still_killed() {
    // The stdin write must sit inside the timeout, because a script that never drains stdin
    // blocks it once the payload exceeds the pipe buffer. Only a real blocked pipe shows that.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (target_id, cipher_id) = (Uuid::new_v4(), Uuid::new_v4());
    let prefix = env_prefix(target_id);

    mount_rotation(
        &api,
        make_cipher_data(&org_key, "old-password"),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
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
                    .join("sleep_no_stdin.ps1")
                    .to_string_lossy()
                    .into_owned(),
            ),
            // 1 MiB clears the pipe buffer on every platform, so the write blocks.
            (format!("{prefix}BULK"), "x".repeat(1024 * 1024)),
        ],
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
    // The containment check is `canonicalize` plus `starts_with`, so only a real link tests it.
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = make_org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (target_id, cipher_id) = (Uuid::new_v4(), Uuid::new_v4());
    let prefix = env_prefix(target_id);

    let root = tempfile::TempDir::new().expect("temp dir");
    let link = root.path().join("escape.sh");
    std::os::unix::fs::symlink("/bin/sh", &link).expect("symlink");

    mount_rotation(
        &api,
        make_cipher_data(&org_key, "old-password"),
        job_id,
        attempt_id,
        target_id,
        cipher_id,
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
