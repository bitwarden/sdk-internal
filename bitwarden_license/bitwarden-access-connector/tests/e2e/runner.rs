//! Runs the real connector against the live server and watches the job through the Seeder.

use std::{path::PathBuf, time::Duration};

use bitwarden_access_connector::executor::{AccessConnectorConfig, RunExit};
use bitwarden_access_token::AccessToken;
use bitwarden_test::play::Play;
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::{task::JoinHandle, time::Instant};
use uuid::Uuid;

use super::scenes::{
    PamAccessConnectorState, PamAccessConnectorStateArgs, PamAccessConnectorStateQuery,
    PamRotationJobState, PamRotationJobStateArgs, PamRotationJobStateQuery, enums::attempt_action,
};
use crate::common::lock_env;

/// How often the seeder is asked for the job's state.
const WATCH_INTERVAL: Duration = Duration::from_millis(200);

/// The connector's poll interval; short so tests don't wait on the default 15 seconds.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What a run left behind.
#[derive(Debug)]
pub struct RunOutcome {
    /// Why `run` ended: `Shutdown` when this module cancelled it, anything else when it stopped on
    /// its own first.
    pub exit: RunExit,
    /// Whether the stop condition held before the deadline or an early exit.
    pub resolved: bool,
    /// The job after the connector stopped.
    pub job: PamRotationJobState,
}

/// A connector running in the background with per-target environment variables set.
///
/// Dropping it cancels the connector and removes the variables.
pub struct RunningConnector {
    cancel: CancellationToken,
    handle: Option<JoinHandle<RunExit>>,
    env_keys: Vec<String>,
}

impl RunningConnector {
    /// Sets `env`, then spawns `run` for `token` against the URLs in `play.config()`.
    pub fn start(
        play: &Play,
        token: AccessToken,
        env: &[(String, String)],
        script_root: Option<PathBuf>,
    ) -> Self {
        {
            let _guard = lock_env();
            // SAFETY: guarded by ENV_LOCK.
            unsafe {
                for (key, value) in env {
                    std::env::set_var(key, value);
                }
            }
        }

        let config = play.config();
        let cfg = AccessConnectorConfig::new_for_test(
            config.api_url.clone(),
            config.identity_url.clone(),
            token,
            POLL_INTERVAL,
            script_root,
        );
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle =
            tokio::spawn(async move { bitwarden_access_connector::run(cfg, task_cancel).await });

        Self {
            cancel,
            handle: Some(handle),
            env_keys: env.iter().map(|(key, _)| key.clone()).collect(),
        }
    }

    /// Whether `run` has returned on its own.
    pub fn has_exited(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Cancels the connector and returns why it ended.
    pub async fn stop(mut self) -> RunExit {
        self.cancel.cancel();
        let handle = self.handle.take().expect("handle is taken once");
        handle.await.expect("connector task panicked")
    }
}

impl Drop for RunningConnector {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _guard = lock_env();
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            for key in &self.env_keys {
                std::env::remove_var(key);
            }
        }
    }
}

/// The job's current state.
pub async fn job_state(play: &Play, job_id: Uuid) -> PamRotationJobState {
    play.query::<PamRotationJobStateQuery>(&PamRotationJobStateArgs { job_id })
        .await
        .expect("PamRotationJobStateQuery")
        .state
}

/// The connector's current state.
pub async fn connector_state(play: &Play, access_connector_id: Uuid) -> PamAccessConnectorState {
    play.query::<PamAccessConnectorStateQuery>(&PamAccessConnectorStateArgs {
        access_connector_id,
    })
    .await
    .expect("PamAccessConnectorStateQuery")
    .state
}

/// Whether some attempt has recorded an outcome.
pub fn has_resolved_attempt(job: &PamRotationJobState) -> bool {
    job.attempts
        .iter()
        .any(|attempt| attempt.action != attempt_action::NONE)
}

/// Runs the connector until an attempt of `job_id` records an outcome, it exits on its own, or
/// `deadline` passes.
pub async fn run_until_resolved(
    play: &Play,
    token: AccessToken,
    job_id: Uuid,
    env: &[(String, String)],
    script_root: Option<PathBuf>,
    deadline: Duration,
) -> RunOutcome {
    run_until(
        play,
        token,
        job_id,
        env,
        script_root,
        deadline,
        has_resolved_attempt,
    )
    .await
}

/// Runs the connector until `done` holds for the job's state, it exits on its own, or `deadline`
/// passes.
pub async fn run_until(
    play: &Play,
    token: AccessToken,
    job_id: Uuid,
    env: &[(String, String)],
    script_root: Option<PathBuf>,
    deadline: Duration,
    done: impl Fn(&PamRotationJobState) -> bool,
) -> RunOutcome {
    let running = RunningConnector::start(play, token, env, script_root);
    let give_up = Instant::now() + deadline;
    let mut resolved = false;

    loop {
        if done(&job_state(play, job_id).await) {
            resolved = true;
            break;
        }
        if running.has_exited() || Instant::now() >= give_up {
            break;
        }
        tokio::time::sleep(WATCH_INTERVAL).await;
    }

    let exit = running.stop().await;
    RunOutcome {
        exit,
        resolved,
        job: job_state(play, job_id).await,
    }
}

/// Runs the connector for `duration` regardless of the job, returning early if it exits on its
/// own. For tests that assert a job is never claimed.
pub async fn run_for(
    play: &Play,
    token: AccessToken,
    job_id: Uuid,
    env: &[(String, String)],
    script_root: Option<PathBuf>,
    duration: Duration,
) -> RunOutcome {
    run_until(play, token, job_id, env, script_root, duration, |_| false).await
}
