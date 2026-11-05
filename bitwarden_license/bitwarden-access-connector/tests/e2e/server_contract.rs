//! Server-contract behaviour against a live server: what the connector refuses, what the server
//! never hands out, who may run, and what the server records about the connector.

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use bitwarden_access_connector::executor::RunExit;
use bitwarden_test::play::{Play, play_test};
use tokio::time::Instant;

use super::{
    cipher::read_login,
    fixture::RotationFixture,
    runner::{
        RunOutcome, RunningConnector, connector_state, has_resolved_attempt, job_state, run_for,
        run_until_resolved,
    },
    scenes::enums::{attempt_action, connector_status, job_action, sync_state},
};

/// How long a never-claimed check keeps the connector polling (50 ms poll interval).
const IDLE_RUN: Duration = Duration::from_secs(4);

/// The deadline for anything the test waits on to resolve.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(60);

/// Whether the script ran at all: each operation writes `<out_path>.<operation>`.
fn script_ran(out_path: &Path) -> bool {
    ["rotate", "verify", "terminate"]
        .iter()
        .any(|operation| PathBuf::from(format!("{}.{operation}", out_path.display())).exists())
}

/// Asserts the connector ran to cancellation without the server ever handing it the job.
fn assert_never_claimed(outcome: &RunOutcome) {
    assert_eq!(outcome.exit, RunExit::Shutdown, "{:?}", outcome.job);
    assert_eq!(outcome.job.action, job_action::NONE, "{:?}", outcome.job);
    assert!(outcome.job.attempts.is_empty(), "{:?}", outcome.job);
    assert!(outcome.job.last_rotation_date.is_none());
}

/// Runs the connector for `fixture` for [`IDLE_RUN`], asserting nothing is claimed and
/// the script never runs.
async fn assert_job_is_never_claimed(play: &Play, fixture: &RotationFixture) {
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    let outcome = run_for(
        play,
        fixture.connector.token(),
        fixture.job_id,
        &env,
        None,
        IDLE_RUN,
    )
    .await;

    assert_never_claimed(&outcome);
    assert!(!script_ran(&out_path), "the script must not run");
}

/// Runs a connector that must refuse the claim it gets, then asserts the refusal: an `Errored`
/// attempt with `TargetUnchanged` whose reason contains `reason`, no script run, no rotation, and
/// the cipher exactly as seeded.
async fn assert_claim_refused_before_target(play: &Play, fixture: &RotationFixture, reason: &str) {
    let before = read_login(
        play,
        fixture.organization_id,
        &fixture.org_key,
        fixture.cipher_id,
    )
    .await;

    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    let outcome = run_until_resolved(
        play,
        fixture.connector.token(),
        fixture.job_id,
        &env,
        None,
        RESOLVE_DEADLINE,
    )
    .await;

    assert!(outcome.resolved, "no attempt resolved: {:?}", outcome.job);
    assert_eq!(outcome.exit, RunExit::Shutdown);
    assert!(!script_ran(&out_path), "the script must not run");

    // The server returns an errored job to the queue with a backoff (and fails it once its
    // retries run out), so the job is never Succeeded and later attempts repeat the first.
    assert_ne!(outcome.job.action, job_action::SUCCEEDED);
    assert!(outcome.job.last_rotation_date.is_none());
    let resolved: Vec<_> = outcome
        .job
        .attempts
        .iter()
        .filter(|attempt| attempt.action != attempt_action::NONE)
        .collect();
    assert!(!resolved.is_empty(), "{:?}", outcome.job);
    for attempt in resolved {
        assert_eq!(attempt.action, attempt_action::ERRORED);
        assert!(!attempt.cipher_updated);
        assert_eq!(attempt.sync_state, Some(sync_state::TARGET_UNCHANGED));
        assert_eq!(
            attempt.claimed_by_access_connector_id,
            fixture.connector.access_connector_id
        );
        let failure = attempt.failure_reason.as_deref().unwrap_or_default();
        assert!(
            failure.starts_with("sealed_data_rejected") && failure.contains(reason),
            "unexpected failure reason {failure:?}, wanted {reason:?}"
        );
    }

    let after = read_login(
        play,
        fixture.organization_id,
        &fixture.org_key,
        fixture.cipher_id,
    )
    .await;
    assert_eq!(after.password, before.password);
    assert_eq!(after.password, fixture.initial_password);
    assert_eq!(after.key, before.key);
    assert_eq!(after.revision_date, before.revision_date);
    assert!(after.password_history.is_empty());
}

/// A cipher without an item key is refused by the pre-flight check as `sealed_data_rejected`
/// (`pre_flight_cipher_without_item_key`), reported `TargetUnchanged`, before any script runs.
#[cfg(unix)]
#[play_test]
async fn keyless_cipher_is_refused_before_the_target_is_touched(play: Play) {
    let fixture = RotationFixture::builder()
        .use_cipher_key(false)
        .seed(&play)
        .await;

    assert_claim_refused_before_target(&play, &fixture, "pre_flight_cipher_without_item_key").await;
}

/// A rotation config sealed for another cipher fails `WorkSnapshot::verify` as
/// `sealed_data_rejected` (`cipher_id_mismatch`), reported `TargetUnchanged`, with no script run.
#[cfg(unix)]
#[play_test]
async fn config_sealed_for_another_cipher_is_refused(play: Play) {
    let fixture = RotationFixture::builder()
        .tamper_config_cipher_id(true)
        .seed(&play)
        .await;

    assert_claim_refused_before_target(&play, &fixture, "cipher_id_mismatch").await;
}

/// A connector that is not assigned to the target never sees the job and keeps polling.
#[cfg(unix)]
#[play_test]
async fn unassigned_connector_never_claims_the_job(play: Play) {
    let fixture = RotationFixture::builder()
        .assign_connector(false)
        .seed(&play)
        .await;

    assert_job_is_never_claimed(&play, &fixture).await;
}

/// A job whose target system was disabled after seeding is not offered or claimable.
#[cfg(unix)]
#[play_test]
async fn disabled_target_job_is_never_claimed(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    fixture.disable_target(&play).await;

    assert_job_is_never_claimed(&play, &fixture).await;
}

/// A job whose rotation config was disabled after seeding is not offered or claimable.
#[cfg(unix)]
#[play_test]
async fn disabled_config_job_is_never_claimed(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    fixture.disable_config(&play).await;

    assert_job_is_never_claimed(&play, &fixture).await;
}

/// An already expired job is not offered or claimable.
#[cfg(unix)]
#[play_test]
async fn expired_job_is_never_claimed(play: Play) {
    let fixture = RotationFixture::builder()
        .job_expires_in_seconds(-60)
        .seed(&play)
        .await;

    assert_job_is_never_claimed(&play, &fixture).await;
}

/// Two connectors assigned to one job race for it: exactly one attempt exists, it is claimed by
/// one of them, the job succeeds, and neither connector stops on its own.
#[cfg(unix)]
#[play_test]
async fn two_connectors_produce_a_single_attempt(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let second = fixture.add_connector(&play).await;

    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    // Both read the same per-target variables; neither is dropped before the job resolves.
    let first_running = RunningConnector::start(&play, fixture.connector.token(), &env, None);
    let second_running = RunningConnector::start(&play, second.token(), &env, None);

    let give_up = Instant::now() + RESOLVE_DEADLINE;
    let job = loop {
        let job = job_state(&play, fixture.job_id).await;
        if job.action == job_action::SUCCEEDED {
            break job;
        }
        assert!(
            !first_running.has_exited() && !second_running.has_exited(),
            "a connector exited early: {job:?}"
        );
        assert!(Instant::now() < give_up, "job did not succeed: {job:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(has_resolved_attempt(&job), "{job:?}");

    // A claimed job can no longer be offered, so a late poll must not add an attempt.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !first_running.has_exited() && !second_running.has_exited(),
        "a connector exited on its own"
    );
    let job = job_state(&play, fixture.job_id).await;
    assert_eq!(job.action, job_action::SUCCEEDED);
    assert_eq!(job.attempts.len(), 1, "{job:?}");
    let attempt = &job.attempts[0];
    assert_eq!(attempt.action, attempt_action::ROTATED);
    assert!(
        [
            fixture.connector.access_connector_id,
            second.access_connector_id
        ]
        .contains(&attempt.claimed_by_access_connector_id),
        "claimed by an unknown connector: {attempt:?}"
    );

    assert_eq!(first_running.stop().await, RunExit::Shutdown);
    assert_eq!(second_running.stop().await, RunExit::Shutdown);
}

/// Starts the connector for `fixture` and waits for it to exit on its own.
async fn exit_on_its_own(play: &Play, fixture: &RotationFixture) -> RunExit {
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    let running = RunningConnector::start(play, fixture.connector.token(), &env, None);
    let give_up = Instant::now() + Duration::from_secs(30);
    while !running.has_exited() && Instant::now() < give_up {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        running.has_exited(),
        "the connector did not exit on its own"
    );
    running.stop().await
}

/// A disabled connector is refused a token by identity, so `run` exits `CredentialRefused` and
/// the job is untouched.
#[cfg(unix)]
#[play_test]
async fn disabled_connector_is_refused_a_token(play: Play) {
    let fixture = RotationFixture::builder()
        .connector_status(connector_status::DISABLED)
        .seed(&play)
        .await;

    assert_eq!(
        exit_on_its_own(&play, &fixture).await,
        RunExit::CredentialRefused
    );
    let job = job_state(&play, fixture.job_id).await;
    assert_eq!(job.action, job_action::NONE);
    assert!(job.attempts.is_empty());
}

/// An organization without `UsePam` is refused a token by identity, so `run` exits
/// `CredentialRefused` and the job is untouched.
#[cfg(unix)]
#[play_test]
async fn connector_of_an_organization_without_pam_is_refused(play: Play) {
    let fixture = RotationFixture::builder().use_pam(false).seed(&play).await;

    assert_eq!(
        exit_on_its_own(&play, &fixture).await,
        RunExit::CredentialRefused
    );
    let job = job_state(&play, fixture.job_id).await;
    assert_eq!(job.action, job_action::NONE);
    assert!(job.attempts.is_empty());
}

/// Every connector-facing route, including an idle poll, records `LastHeartbeatDate` on the
/// connector (null before its first request).
#[cfg(unix)]
#[play_test]
async fn idle_polling_records_a_heartbeat(play: Play) {
    // Unassigned, so the polls stay idle and the job is never touched.
    let fixture = RotationFixture::builder()
        .assign_connector(false)
        .seed(&play)
        .await;
    let before = connector_state(&play, fixture.connector.access_connector_id).await;
    assert!(
        before.last_heartbeat_date.is_none(),
        "heartbeat before any request: {before:?}"
    );

    assert_job_is_never_claimed(&play, &fixture).await;

    let after = connector_state(&play, fixture.connector.access_connector_id).await;
    assert!(
        after.last_heartbeat_date.is_some(),
        "no heartbeat after polling: {after:?}"
    );
}

/// Kills the child on drop so a failing test never leaks a connector.
struct ChildGuard {
    child: Child,
    stderr_path: PathBuf,
}

impl ChildGuard {
    /// The connector's stderr so far, for failure messages.
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The real `bwac run --config <file>` binary, configured by file and environment only, rotates a
/// job on its first poll (the loop's first tick is immediate, not after `poll_interval`), then
/// exits 0 on SIGTERM.
#[cfg(unix)]
#[play_test]
async fn bwac_binary_rotates_a_job_and_exits_cleanly_on_sigterm(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;

    let work_dir = tempfile::tempdir().expect("tempdir");
    let out_path = work_dir.path().join("out");
    let config_path = work_dir.path().join("bwac.toml");
    let stderr_path = work_dir.path().join("stderr.log");
    let config = play.config();
    std::fs::write(
        &config_path,
        format!(
            "poll_interval = 15\n\n[environment]\napi = {:?}\nidentity = {:?}\n",
            config.api_url, config.identity_url
        ),
    )
    .expect("write config");

    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);
    let mut command = Command::new(env!("CARGO_BIN_EXE_bwac"));
    command
        .args(["run", "--config"])
        .arg(&config_path)
        .env_clear()
        .env("BWAC_TOKEN", fixture.connector.token_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_path).expect("create stderr log"),
        ));
    // Forward the variables bwac and the script need for PATH, TLS, proxying and logging.
    const FORWARDED_ENV: &[&str] = &[
        "PATH",
        "HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "RUST_LOG",
    ];
    for name in FORWARDED_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(env.iter().map(|(key, value)| (key, value)));
    let mut bwac = ChildGuard {
        child: command.spawn().expect("spawn bwac"),
        stderr_path,
    };

    let give_up = Instant::now() + RESOLVE_DEADLINE;
    let job = loop {
        let job = job_state(&play, fixture.job_id).await;
        if has_resolved_attempt(&job) {
            break job;
        }
        if let Some(status) = bwac.child.try_wait().expect("try_wait") {
            panic!("bwac exited early ({status}): {job:?}\n{}", bwac.stderr());
        }
        assert!(
            Instant::now() < give_up,
            "no attempt resolved: {job:?}\n{}",
            bwac.stderr()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(job.action, job_action::SUCCEEDED, "{}", bwac.stderr());
    assert_eq!(job.attempts.len(), 1);
    assert_eq!(job.attempts[0].action, attempt_action::ROTATED);
    assert_eq!(
        job.attempts[0].claimed_by_access_connector_id,
        fixture.connector.access_connector_id
    );
    assert!(
        PathBuf::from(format!("{}.rotate", out_path.display())).exists(),
        "the rotate script did not run"
    );

    // `main` handles SIGTERM by cancelling the loop, which closes the session and exits 0.
    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(bwac.child.id().to_string())
        .status()
        .expect("run kill");
    assert!(signalled.success(), "kill -TERM failed");
    let give_up = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = bwac.child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < give_up,
            "bwac ignored SIGTERM\n{}",
            bwac.stderr()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status.code(), Some(0), "{}", bwac.stderr());
}
