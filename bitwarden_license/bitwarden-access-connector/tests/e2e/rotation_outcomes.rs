//! Rotation outcomes other than plain success: session termination, script failures, retries and
//! misconfiguration, against a live server.
//!
//! The server returns a job to pending after each errored attempt and fails it once
//! `PamRotationOptions.MaxAttempts` (default 5) attempts have errored, so the failure tests wait
//! for the job to reach `Failed` and assert on every attempt. The stored failure reason is the
//! connector's `errorCode`, then `": "` and the detail (`ReportRotationFailedRequestModel`).

use std::{path::Path, time::Duration};

use bitwarden_access_connector::executor::RunExit;
use bitwarden_test::play::{Play, play_test};

use super::{
    cipher::{DecryptedLogin, read_login},
    fixture::RotationFixture,
    runner::{RunOutcome, run_until, run_until_resolved},
    scenes::{
        PamRotationJobState,
        enums::{attempt_action, job_action, session_termination, sync_state},
    },
};

const DEADLINE: Duration = Duration::from_secs(60);

/// Long enough for the server's retry backoff (1s, 2s, 4s, 8s by default) between five attempts.
const FAILURE_DEADLINE: Duration = Duration::from_secs(90);

async fn read(play: &Play, fixture: &RotationFixture) -> DecryptedLogin {
    read_login(
        play,
        fixture.organization_id,
        &fixture.org_key,
        fixture.cipher_id,
    )
    .await
}

fn read_payload(out_path: &Path, operation: &str) -> serde_json::Value {
    let path = format!("{}.{operation}", out_path.display());
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the {operation} script did not run ({path}): {e}"));
    serde_json::from_str(&body).expect("payload is JSON")
}

fn was_run(out_path: &Path, operation: &str) -> bool {
    Path::new(&format!("{}.{operation}", out_path.display())).exists()
}

/// Runs the connector until the job's retry budget is exhausted.
async fn run_until_failed(
    play: &Play,
    fixture: &RotationFixture,
    env: &[(String, String)],
) -> RunOutcome {
    run_until(
        play,
        fixture.connector.token(),
        fixture.job_id,
        env,
        None,
        FAILURE_DEADLINE,
        |job| job.action == job_action::FAILED,
    )
    .await
}

/// Asserts that the job failed and every attempt errored with the same reason and sync state.
fn assert_failed(outcome: &RunOutcome, failure_reason: &str, sync: i32) {
    assert!(outcome.resolved, "the job never failed: {:?}", outcome.job);
    assert_eq!(outcome.exit, RunExit::Shutdown);
    let job: &PamRotationJobState = &outcome.job;
    assert_eq!(job.action, job_action::FAILED);
    assert!(!job.attempts.is_empty(), "the job has no attempts");
    for attempt in &job.attempts {
        assert_eq!(attempt.action, attempt_action::ERRORED, "{attempt:?}");
        assert!(!attempt.cipher_updated, "{attempt:?}");
        assert_eq!(
            attempt.failure_reason.as_deref(),
            Some(failure_reason),
            "{attempt:?}"
        );
        assert_eq!(attempt.sync_state, Some(sync), "{attempt:?}");
        assert_eq!(attempt.session_termination, None, "{attempt:?}");
    }
}

/// Asserts the cipher is exactly as seeded.
async fn assert_cipher_untouched(play: &Play, fixture: &RotationFixture, before: &DecryptedLogin) {
    let after = read(play, fixture).await;
    assert_eq!(after.password, fixture.initial_password);
    assert_eq!(after.password_history, before.password_history);
    assert_eq!(after.key, before.key, "the item key is unchanged");
    assert_eq!(after.revision_date, before.revision_date);
    assert_eq!(after.password_revision_date, before.password_revision_date);
}

/// When the claim asks for session termination and the script's `terminate` succeeds, the attempt
/// records `Terminated`, and the terminate payload carries no password.
#[cfg(unix)]
#[play_test]
async fn terminate_sessions_success_is_recorded_as_terminated(play: Play) {
    let fixture = RotationFixture::builder()
        .terminate_sessions(true)
        .seed(&play)
        .await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    let outcome = run_until_resolved(
        &play,
        fixture.connector.token(),
        fixture.job_id,
        &env,
        None,
        DEADLINE,
    )
    .await;

    assert!(outcome.resolved, "no attempt resolved: {:?}", outcome.job);
    assert_eq!(outcome.job.action, job_action::SUCCEEDED);
    assert_eq!(outcome.job.attempts.len(), 1);
    let attempt = &outcome.job.attempts[0];
    assert_eq!(attempt.action, attempt_action::ROTATED);
    assert!(attempt.cipher_updated);
    assert_eq!(
        attempt.session_termination,
        Some(session_termination::TERMINATED)
    );

    let terminate = read_payload(&out_path, "terminate");
    assert_eq!(terminate["operation"], "terminate");
    assert_eq!(
        terminate["accountIdentity"],
        fixture.account_identity.as_str()
    );
    assert!(
        terminate.get("newPassword").is_none(),
        "terminate must not receive the password: {terminate}"
    );
    let rotate = read_payload(&out_path, "rotate");
    let new_password = rotate["newPassword"]
        .as_str()
        .expect("rotate got a password");
    assert_eq!(read(&play, &fixture).await.password, new_password);
}

/// A failing `terminate` never fails the rotation: the vault is updated, the job succeeds and the
/// attempt records `TermFailed` (`Attempt::terminate_sessions`; exit 1 is permanent, so no retry).
#[cfg(unix)]
#[play_test]
async fn terminate_sessions_failure_still_succeeds_the_rotation(play: Play) {
    let fixture = RotationFixture::builder()
        .terminate_sessions(true)
        .seed(&play)
        .await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env(
        "record_and_exit.sh",
        &out_path,
        &[("EXIT_CODE_TERMINATE", "1")],
    );

    let outcome = run_until_resolved(
        &play,
        fixture.connector.token(),
        fixture.job_id,
        &env,
        None,
        DEADLINE,
    )
    .await;

    assert!(outcome.resolved, "no attempt resolved: {:?}", outcome.job);
    assert_eq!(outcome.job.action, job_action::SUCCEEDED);
    assert_eq!(outcome.job.attempts.len(), 1);
    let attempt = &outcome.job.attempts[0];
    assert_eq!(attempt.action, attempt_action::ROTATED);
    assert!(attempt.cipher_updated);
    assert_eq!(attempt.failure_reason, None);
    assert_eq!(
        attempt.session_termination,
        Some(session_termination::TERM_FAILED)
    );
    assert!(was_run(&out_path, "terminate"), "terminate did not run");

    let rotate = read_payload(&out_path, "rotate");
    let new_password = rotate["newPassword"]
        .as_str()
        .expect("rotate got a password");
    assert_eq!(read(&play, &fixture).await.password, new_password);
}

/// A rotate that exits 1 ("fatal, target unchanged") fails every attempt as `script_failed: exit
/// code 1` with the target unchanged. Verify never runs and the cipher is untouched.
#[cfg(unix)]
#[play_test]
async fn fatal_rotate_failure_leaves_target_and_cipher_unchanged(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read(&play, &fixture).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env(
        "record_and_exit.sh",
        &out_path,
        &[("EXIT_CODE_ROTATE", "1")],
    );

    let outcome = run_until_failed(&play, &fixture, &env).await;

    assert_failed(
        &outcome,
        "script_failed: exit code 1",
        sync_state::TARGET_UNCHANGED,
    );
    assert!(was_run(&out_path, "rotate"), "rotate did not run");
    assert!(
        !was_run(&out_path, "verify"),
        "verify must not run after a failed rotate"
    );
    assert_cipher_untouched(&play, &fixture, &before).await;
}

/// A rotate that exits 4 ("transient, retry") is tried `max_retry_attempts` (2 in
/// `new_for_test`) times per attempt, then reported as `script_failed: exit code 4` with the
/// target unchanged. The cipher is untouched.
#[cfg(unix)]
#[play_test]
async fn transient_rotate_failure_exhausts_retries(play: Play) {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read(&play, &fixture).await;

    // record_and_exit.sh overwrites its output on each run, so count invocations with a script
    // that appends one line per run.
    let dir = tempfile::tempdir().expect("tempdir");
    let count_path = dir.path().join("invocations");
    let script_path = dir.path().join("always_transient.sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\ncat > /dev/null\necho \"$1\" >> '{}'\nexit 4\n",
            count_path.display()
        ),
    )
    .expect("write script");
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod script");
    let env = fixture.env(&[("SCRIPT", script_path.to_str().expect("utf8 path"))]);

    let outcome = run_until_failed(&play, &fixture, &env).await;

    assert_failed(
        &outcome,
        "script_failed: exit code 4",
        sync_state::TARGET_UNCHANGED,
    );
    let invocations = std::fs::read_to_string(&count_path).expect("the script ran");
    let lines: Vec<&str> = invocations.lines().collect();
    assert!(
        lines.iter().all(|operation| *operation == "rotate"),
        "only rotate may run: {lines:?}"
    );
    assert_eq!(
        lines.len(),
        outcome.job.attempts.len() * 2,
        "each attempt tries rotate max_retry_attempts (2) times"
    );
    assert_cipher_untouched(&play, &fixture, &before).await;
}

/// Pins the executor's rule that a failed verify reports `TargetUpdated` (the target already has
/// the new password, so the vault is stale) and never writes the cipher: the cipher write comes
/// after verify (`Attempt::run`, `TargetStep::failure_sync`). The reason is the script's own
/// `script_failed: exit code 1`.
#[cfg(unix)]
#[play_test]
async fn verify_failure_reports_target_updated_and_skips_the_cipher_write(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read(&play, &fixture).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env(
        "record_and_exit.sh",
        &out_path,
        &[("EXIT_CODE_VERIFY", "1")],
    );

    let outcome = run_until_failed(&play, &fixture, &env).await;

    assert_failed(
        &outcome,
        "script_failed: exit code 1",
        sync_state::TARGET_UPDATED,
    );
    assert!(was_run(&out_path, "rotate"), "rotate did not run");
    assert!(was_run(&out_path, "verify"), "verify did not run");
    assert_cipher_untouched(&play, &fixture, &before).await;
}

/// With no `SCRIPT` credential the resolver fails the attempt before anything runs:
/// `credentials_unresolved` naming the missing variable, target unchanged.
#[cfg(unix)]
#[play_test]
async fn missing_script_credential_fails_as_credentials_unresolved(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read(&play, &fixture).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.env(&[("OUT_PATH", out_path.to_str().expect("utf8 path"))]);

    let outcome = run_until_failed(&play, &fixture, &env).await;

    assert_failed(
        &outcome,
        &format!(
            "credentials_unresolved: missing vars: {}SCRIPT",
            fixture.env_prefix
        ),
        sync_state::TARGET_UNCHANGED,
    );
    assert!(!was_run(&out_path, "rotate"), "nothing may run");
    assert_cipher_untouched(&play, &fixture, &before).await;
}

/// A `SCRIPT` that does not exist fails the attempt before anything runs:
/// `credentials_unresolved` with `ScriptNotFound`, target unchanged.
#[cfg(unix)]
#[play_test]
async fn nonexistent_script_fails_as_credentials_unresolved(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read(&play, &fixture).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let missing = out_dir.path().join("no-such-script.sh");
    let env = fixture.env(&[
        ("SCRIPT", missing.to_str().expect("utf8 path")),
        ("OUT_PATH", out_path.to_str().expect("utf8 path")),
    ]);

    let outcome = run_until_failed(&play, &fixture, &env).await;

    assert_failed(
        &outcome,
        "credentials_unresolved: error kind: ScriptNotFound",
        sync_state::TARGET_UNCHANGED,
    );
    assert!(!was_run(&out_path, "rotate"), "nothing may run");
    assert_cipher_untouched(&play, &fixture, &before).await;
}
