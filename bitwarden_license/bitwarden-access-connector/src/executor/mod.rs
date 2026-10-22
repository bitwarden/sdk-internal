//! Rotation job executor: scheduling, retry, and lifecycle management.
//!
//! No socket exists, so a network blip does not close the session; only shutdown does.

pub(crate) mod retry;
pub(crate) mod rotation;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use bitwarden_access_token::AccessToken;
use bitwarden_core::{Client, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_pam::{RotationFailureCode, RotationSyncState, WorkSnapshot};
use bitwarden_pam_sealed::SealedTargetSystemKind;
use bitwarden_threading::cancellation_token::CancellationToken;
use retry::RetryCfg;
use rotation::{AbortReason, ExecutionContext, ExecutionResult, LastOk, execute};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior, interval},
};
use uuid::Uuid;

use crate::{
    api::{
        AccessConnectorClient, AccessConnectorClientExt as _, REQUEST_TIMEOUT, build_sdk_client,
        models::{ApiError, JobRef},
    },
    auth::{
        identity::IdentityClient,
        session::{SessionError, SessionLost, SessionManager},
    },
    error::SafeDetail,
    integrations::{
        IntegrationRegistry,
        entra::EntraIntegration,
        scripting::{CustomScriptIntegration, PowershellConfig, ProcessScriptRunner},
    },
    resolver::{
        CredentialResolver,
        config::{ConfigCredentialResolver, TargetEntry},
    },
    sys::{Platform, SystemEnv},
};

/// Why the run loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunExit {
    /// Shutdown was requested.
    Shutdown,
    /// The credential was rejected or revoked; it must be reissued.
    CredentialRefused,
    /// Startup authentication failed, but not because the credential was refused.
    StartupFailed,
    /// The connector is not eligible for the rotation endpoints.
    NotEligible,
}

/// Configuration for the connector run loop, validated by `Config::from_cli`.
pub struct AccessConnectorConfig {
    pub(crate) api_url: String,
    pub(crate) identity_url: String,
    pub(crate) token: AccessToken,
    /// How often the connector polls for new jobs (default: 15 s).
    pub(crate) poll_interval: Duration,
    /// How often the heartbeat fires during an executing rotation (default: 30 s).
    pub(crate) heartbeat_interval: Duration,
    /// Time without server contact before the gate pauses target-side steps (default: 60 s).
    pub(crate) offline_grace: Duration,
    pub(crate) retry_cfg: RetryCfg,
    pub(crate) script_root: Option<PathBuf>,
    /// Script execution timeout for the `CustomScript` integration (default: 60 s).
    pub(crate) script_timeout: Duration,
    /// Explicit PowerShell host path; `None` discovers one on `PATH`.
    pub(crate) powershell_path: Option<PathBuf>,
    /// `-ExecutionPolicy` value passed to the PowerShell host (default: `Bypass`).
    pub(crate) powershell_execution_policy: String,
    /// Whether to enable the Entra verify probe (ROPC-based; off by default).
    pub(crate) entra_verify_probe: bool,
    /// Per-target credential overrides from the `[targets]` config section.
    pub(crate) targets: HashMap<Uuid, TargetEntry>,
}

impl AccessConnectorConfig {
    /// Builds a config for integration tests, bypassing validation.
    #[doc(hidden)]
    pub fn new_for_test(
        api_url: String,
        identity_url: String,
        token: AccessToken,
        poll_interval: Duration,
        script_root: Option<PathBuf>,
    ) -> Self {
        Self {
            api_url,
            identity_url,
            token,
            poll_interval,
            heartbeat_interval: Duration::from_millis(500),
            offline_grace: Duration::from_secs(60),
            retry_cfg: RetryCfg {
                max_retry_attempts: 2,
                retry_base_delay: Duration::from_millis(10),
            },
            script_root,
            script_timeout: Duration::from_secs(10),
            powershell_path: None,
            powershell_execution_policy: "Bypass".to_string(),
            entra_verify_probe: false,
            targets: HashMap::new(),
        }
    }
}

/// Loop outcome of one stage: the value to carry on with, skip to the next tick, or exit.
enum Step<T> {
    Next(T),
    Skip,
    Exit(RunExit),
}

/// Authenticated connector state shared by the stages of the run loop.
struct Worker {
    ctx: ExecutionContext,
    api: AccessConnectorClient,
    key_store: KeyStore<KeySlotIds>,
    heartbeat_interval: Duration,
}

/// Runs the connector poll loop. A revoked session exits as [`RunExit::CredentialRefused`], other
/// startup failures as [`RunExit::StartupFailed`], and a 404 that survives a refresh probe as
/// [`RunExit::NotEligible`].
pub(crate) async fn run(cfg: AccessConnectorConfig, cancel: CancellationToken) -> RunExit {
    let poll_interval = cfg.poll_interval;
    let worker = match Worker::start(cfg, cancel.clone()).await {
        Ok(w) => w,
        Err(exit) => return exit,
    };

    let mut poll_ticker = interval(poll_interval);
    poll_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut poll_backoff = Duration::from_secs(1);

    let exit = loop {
        tokio::select! {
            _ = cancel.cancelled() => break RunExit::Shutdown,
            _ = poll_ticker.tick() => {}
        }

        let jobs = match worker.poll(&mut poll_backoff).await {
            Step::Next(jobs) => jobs,
            Step::Skip => continue,
            Step::Exit(exit) => break exit,
        };

        let snap = match worker.claim_one(jobs).await {
            Step::Next(snap) => snap,
            Step::Skip => continue,
            Step::Exit(exit) => break exit,
        };

        if let Some(exit) = worker.rotate(snap).await {
            break exit;
        }
    };

    if exit == RunExit::Shutdown {
        tracing::info!("shutdown requested; closing session");
        worker.ctx.session.close().await;
    }
    exit
}

impl Worker {
    /// Authenticates and assembles the loop state, or returns the exit for a failed startup.
    async fn start(cfg: AccessConnectorConfig, cancel: CancellationToken) -> Result<Self, RunExit> {
        let identity_client = match IdentityClient::new(cfg.identity_url.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("failed to build identity client: {e}");
                return Err(RunExit::StartupFailed);
            }
        };

        // URLs only, never the token.
        tracing::info!(
            api_url = %cfg.api_url,
            identity_url = %cfg.identity_url,
            poll_interval_secs = cfg.poll_interval.as_secs(),
            heartbeat_interval_secs = cfg.heartbeat_interval.as_secs(),
            configured_targets = cfg.targets.len(),
            "access connector starting"
        );

        // Built first, since the session installs the org key into the client's key store.
        let (connectivity_tx, connectivity_rx) = watch::channel(Instant::now());
        let (sdk_client, handler) = build_sdk_client(
            cfg.api_url.clone(),
            cfg.identity_url.clone(),
            REQUEST_TIMEOUT,
            connectivity_tx,
        );

        let key_store = handler
            .key_store()
            .expect("ClientBuilder::build calls initialize_middleware, which sets the key store");

        let integrations = build_integrations(&cfg);

        // `SessionManager::new` backs off internally; `select!` lets cancellation interrupt it.
        let session = tokio::select! {
            result = SessionManager::new(identity_client, cfg.token, key_store.clone()) => {
                match result {
                    Ok(s) => s,
                    Err(SessionError::Lost(SessionLost::Revoked)) => {
                        tracing::warn!("credential refused at startup");
                        return Err(RunExit::CredentialRefused);
                    }
                    Err(e) => {
                        // Transient failures outlasted the startup retries.
                        tracing::error!("startup authentication failed: {e}");
                        return Err(RunExit::StartupFailed);
                    }
                }
            }
            _ = cancel.cancelled() => {
                tracing::info!("shutdown requested during startup; exiting");
                return Err(RunExit::Shutdown);
            }
        };

        handler.set_session(Arc::clone(&session));

        let api = sdk_client.access_connector();

        let resolver: Arc<dyn CredentialResolver> = Arc::new(ConfigCredentialResolver::new(
            cfg.targets,
            Arc::new(SystemEnv),
        ));

        // `SessionManager::new` authenticates eagerly, so the claim is already available.
        let Some(organization_id) = session.organization_id().await else {
            tracing::error!("access token carries no usable organization claim");
            return Err(RunExit::CredentialRefused);
        };

        let last_ok: LastOk = Arc::new(move || *connectivity_rx.borrow());

        Ok(Self {
            ctx: ExecutionContext {
                client: sdk_client,
                session,
                integrations,
                resolver,
                organization_id,
                retry_cfg: cfg.retry_cfg,
                offline_grace: cfg.offline_grace,
                last_ok,
                cancel,
            },
            api,
            key_store,
            heartbeat_interval: cfg.heartbeat_interval,
        })
    }

    /// Fetches claimable jobs, backing off on transient errors.
    async fn poll(&self, backoff: &mut Duration) -> Step<Vec<JobRef>> {
        const BACKOFF_CAP: Duration = Duration::from_secs(60);

        match self.api.poll_jobs().await {
            Ok(jobs) => {
                *backoff = Duration::from_secs(1);
                tracing::debug!(claimable_jobs = jobs.len(), "poll tick");
                Step::Next(jobs)
            }
            Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                tracing::warn!("credential refused while polling");
                Step::Exit(RunExit::CredentialRefused)
            }
            Err(ApiError::NotEligible) => {
                // Tell a revoked credential from an organization that lost access.
                self.handle_not_eligible()
                    .await
                    .map_or(Step::Skip, Step::Exit)
            }
            Err(ApiError::Transient(msg)) => {
                tracing::warn!("transient poll error: {msg}; backing off {backoff:?}");
                tokio::select! {
                    _ = tokio::time::sleep(*backoff) => {}
                    _ = self.ctx.cancel.cancelled() => return Step::Exit(RunExit::Shutdown),
                }
                *backoff = (*backoff * 2).min(BACKOFF_CAP);
                Step::Skip
            }
            Err(e) => {
                tracing::warn!("poll error (non-transient): {e}");
                Step::Skip
            }
        }
    }

    /// Claims the first job that is still available; skips the tick when none is.
    async fn claim_one(&self, jobs: Vec<JobRef>) -> Step<WorkSnapshot> {
        for job in jobs {
            match self.api.claim(job.id).await {
                Ok(Some(s)) => {
                    tracing::info!(
                        job_id = %s.job_id,
                        target_system_name = %s.target_system_name,
                        "claimed rotation job"
                    );
                    return Step::Next(s); // at most one claim per tick
                }
                Ok(None) => {
                    tracing::debug!(job_id = %job.id, "claim race lost (409); trying next job");
                }
                Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                    tracing::warn!("credential refused while claiming a job");
                    return Step::Exit(RunExit::CredentialRefused);
                }
                Err(ApiError::NotEligible) => {
                    return self
                        .handle_not_eligible()
                        .await
                        .map_or(Step::Skip, Step::Exit);
                }
                Err(e) => {
                    tracing::warn!("claim error: {e}");
                    return Step::Skip;
                }
            }
        }
        Step::Skip
    }

    /// Verifies and executes a claimed job; returns an exit only when the credential is refused.
    async fn rotate(&self, snap: WorkSnapshot) -> Option<RunExit> {
        // A rejected job never reaches the resolver, an integration or the cipher route.
        let attempt_id = snap.attempt_id;
        let verified = match snap.verify(&self.key_store, self.ctx.organization_id) {
            Ok(v) => v,
            Err(rejection) => {
                tracing::warn!(
                    attempt_id = %attempt_id,
                    rejection = rejection.as_str(),
                    "rotation job rejected: sealed data check failed"
                );
                rotation::report_failure_absorb(
                    &self.api,
                    attempt_id,
                    RotationFailureCode::SealedDataRejected,
                    Some(SafeDetail::from_seal_rejection(rejection.as_str())),
                    RotationSyncState::TargetUnchanged,
                )
                .await;
                return None;
            }
        };

        // Keeps the connectivity watch fresh during the rotation.
        let heartbeat_cancel = self.ctx.cancel.child_token();
        let heartbeat_handle = spawn_heartbeat(
            self.ctx.client.clone(),
            self.heartbeat_interval,
            heartbeat_cancel.clone(),
        );

        let result = execute(verified, &self.ctx).await;

        heartbeat_cancel.cancel();
        let _ = heartbeat_handle.await;

        match result {
            ExecutionResult::Reported => {
                tracing::debug!(attempt_id = %attempt_id, "rotation attempt reported");
                None
            }
            ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Revoked)) => {
                tracing::warn!("credential refused during rotation");
                Some(RunExit::CredentialRefused)
            }
            ExecutionResult::Unreported(reason) => {
                tracing::info!("rotation attempt aborted (unreported): {reason:?}");
                None
            }
        }
    }

    /// Forces a token refresh to tell a revoked credential from a connector that is not eligible.
    /// `None` means the 404 did not survive the refresh (or a transient error hid it); keep
    /// polling.
    async fn handle_not_eligible(&self) -> Option<RunExit> {
        let session = &self.ctx.session;

        // The current bearer is the stale token to refresh.
        let stale = match session.bearer(None).await {
            Ok(t) => t,
            Err(SessionError::Lost(SessionLost::Revoked)) => {
                return Some(RunExit::CredentialRefused);
            }
            Err(_) => String::new(),
        };

        match session.force_refresh(&stale, None).await {
            Ok(_) => {}
            Err(SessionError::Lost(SessionLost::Revoked)) => {
                return Some(RunExit::CredentialRefused);
            }
            Err(_) => {
                // Transient failure; keep polling.
                return None;
            }
        }

        match self.api.poll_jobs().await {
            Err(ApiError::NotEligible) => Some(RunExit::NotEligible),
            Err(ApiError::SessionLost(SessionLost::Revoked)) => Some(RunExit::CredentialRefused),
            _ => None,
        }
    }
}

/// Registers the integrations the connector can drive.
fn build_integrations(cfg: &AccessConnectorConfig) -> Arc<IntegrationRegistry> {
    let mut registry = IntegrationRegistry::new();

    let custom_script = Arc::new(CustomScriptIntegration {
        script_root: cfg.script_root.clone(),
        timeout: cfg.script_timeout,
        powershell: PowershellConfig {
            host: cfg.powershell_path.clone(),
            execution_policy: cfg.powershell_execution_policy.clone(),
        },
        platform: Platform::system(),
        runner: Arc::new(ProcessScriptRunner),
    });
    registry.register(SealedTargetSystemKind::CustomScript, custom_script);

    let entra = Arc::new(EntraIntegration::new(cfg.entra_verify_probe));
    registry.register(SealedTargetSystemKind::Entra, entra);

    Arc::new(registry)
}

/// Polls the jobs endpoint for the connectivity bump until `cancel` fires.
fn spawn_heartbeat(
    client: Client,
    interval_period: Duration,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(interval_period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    tracing::debug!("heartbeat tick");
                    let _ = client.access_connector().poll_jobs().await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{sync::watch, time::Instant};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{
        api::{REQUEST_TIMEOUT, build_sdk_client},
        auth::session::SessionManager,
        test_support::{access_token_tagged, encrypted_payload_for, test_org_id, test_token},
    };

    /// `bearer` is a short tag, expanded to a real JWT so the `organization` claim parses.
    fn identity_ok(bearer: &str, encrypted_payload: &str) -> ResponseTemplate {
        let bearer = access_token_tagged(test_org_id(), bearer);
        ResponseTemplate::new(200)
            .set_body_string(format!(
                r#"{{"access_token":"{bearer}","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
            ))
            .insert_header("content-type", "application/json")
    }

    /// Mounts a `/connect/token` mock that succeeds, for at most `times` requests when given.
    async fn mount_identity_ok(server: &MockServer, times: Option<u64>) {
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);
        let mock = Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_ok("tok", &payload));
        match times {
            Some(n) => mock.up_to_n_times(n).mount(server).await,
            None => mock.mount(server).await,
        }
    }

    async fn make_session(identity_server: &MockServer) -> Arc<SessionManager> {
        mount_identity_ok(identity_server, None).await;

        let identity = IdentityClient::new(identity_server.uri()).unwrap();
        SessionManager::new(
            identity,
            test_token(),
            bitwarden_crypto::KeyStore::default(),
        )
        .await
        .unwrap()
    }

    fn make_client(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> (Client, watch::Receiver<Instant>) {
        let (tx, rx) = watch::channel(Instant::now());
        let (client, handler) = build_sdk_client(
            api_server.uri(),
            "http://identity.invalid".to_owned(),
            REQUEST_TIMEOUT,
            tx,
        );
        handler.set_session(session);
        (client, rx)
    }

    /// Mounts a `/rotation/jobs` mock answering `response`, for at most `times` requests when
    /// given.
    async fn mount_jobs(server: &MockServer, response: ResponseTemplate, times: Option<u64>) {
        let mock = Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(response);
        match times {
            Some(n) => mock.up_to_n_times(n).mount(server).await,
            None => mock.mount(server).await,
        }
    }

    /// A jobs list offering each `(job id, target system id)` pair.
    fn jobs(refs: &[(Uuid, Uuid)]) -> ResponseTemplate {
        let data: Vec<_> = refs
            .iter()
            .map(|(job_id, target_system_id)| {
                serde_json::json!({"jobId": job_id, "targetSystemId": target_system_id})
            })
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "data": data }))
            .insert_header("content-type", "application/json")
    }

    fn empty_jobs() -> ResponseTemplate {
        jobs(&[])
    }

    /// A successful claim of `job_id` whose sealed blobs are opaque, so verification rejects them.
    fn claim_ok(job_id: Uuid, attempt_id: Uuid) -> ResponseTemplate {
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "attemptId": attempt_id,
                "jobId": job_id,
                "targetSystemId": Uuid::new_v4(),
                "targetSystemName": "test",
                "cipherId": Uuid::new_v4(),
                "rotationConfigSealedData": "opaque-config-blob",
                "rotationConfigWrappedKey": "opaque-config-key",
                "executeBy": execute_by
            }))
            .insert_header("content-type", "application/json")
    }

    fn test_cfg(api_server: &MockServer, identity_server: &MockServer) -> AccessConnectorConfig {
        AccessConnectorConfig::new_for_test(
            api_server.uri(),
            identity_server.uri(),
            test_token(),
            Duration::from_millis(30),
            None,
        )
    }

    /// Number of requests `server` received for `method_name` on a path ending with `suffix`.
    async fn count_requests(server: &MockServer, method_name: &str, suffix: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == method_name && r.url.path().ends_with(suffix))
            .count()
    }

    /// Polls until `server` has received `n` requests for `method_name` on a path ending with
    /// `suffix`.
    async fn wait_for_requests(server: &MockServer, method_name: &str, suffix: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let count = count_requests(server, method_name, suffix).await;
            if count >= n {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "expected {n} {method_name} requests ending with {suffix} within 10s, got {count}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn single_flight_only_one_claim_per_tick() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        mount_identity_ok(&identity_server, None).await;

        let job1 = Uuid::new_v4();
        let job2 = Uuid::new_v4();
        let job3 = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();

        // Offer all three jobs once so the claim cycle doesn't repeat.
        mount_jobs(
            &api_server,
            jobs(&[
                (job1, Uuid::new_v4()),
                (job2, Uuid::new_v4()),
                (job3, Uuid::new_v4()),
            ]),
            Some(1),
        )
        .await;
        mount_jobs(&api_server, empty_jobs(), None).await;

        // job1 loses its race, so the loop moves on to job2.
        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job1}/claim"
            )))
            .respond_with(ResponseTemplate::new(409))
            .mount(&api_server)
            .await;

        // job2's claim succeeds, but its sealed blobs are rejected, so nothing executes.
        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job2}/claim"
            )))
            .respond_with(claim_ok(job2, attempt_id))
            .mount(&api_server)
            .await;

        // job3 would also succeed, so claiming it would show the loop did not stop.
        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job3}/claim"
            )))
            .respond_with(claim_ok(job3, Uuid::new_v4()))
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/failure"
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        let cfg = test_cfg(&api_server, &identity_server);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run(cfg, cancel_clone).await });

        wait_for_requests(
            &api_server,
            "POST",
            &format!("/attempts/{attempt_id}/failure"),
            1,
        )
        .await;
        cancel.cancel();
        let exit = handle.await.expect("task panicked");
        assert_eq!(exit, RunExit::Shutdown);

        let claims = |job: Uuid| {
            let suffix = format!("/jobs/{job}/claim");
            let server = &api_server;
            async move { count_requests(server, "POST", &suffix).await }
        };
        assert!(
            claims(job1).await >= 1,
            "job1 should have been claimed (and lost)"
        );
        assert!(claims(job2).await >= 1, "job2 should have been claimed");
        assert_eq!(
            claims(job3).await,
            0,
            "the loop must stop after the first successful claim in a tick"
        );
    }

    #[tokio::test]
    async fn heartbeat_polls_jobs_until_cancelled() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server).await;
        let (client, _rx) = make_client(&api_server, Arc::clone(&session));

        mount_jobs(&api_server, empty_jobs(), None).await;

        let heartbeat_interval = Duration::from_millis(20);
        let cancel = CancellationToken::new();
        let handle = spawn_heartbeat(client, heartbeat_interval, cancel.clone());

        wait_for_requests(&api_server, "GET", "/access-connectors/rotation/jobs", 2).await;

        cancel.cancel();
        handle.await.expect("heartbeat task panicked");
        let count_after_stop =
            count_requests(&api_server, "GET", "/access-connectors/rotation/jobs").await;

        // Wait several intervals to confirm no new calls.
        tokio::time::sleep(heartbeat_interval * 5).await;

        let count_final =
            count_requests(&api_server, "GET", "/access-connectors/rotation/jobs").await;
        assert_eq!(
            count_after_stop, count_final,
            "no heartbeat calls after cancellation"
        );
        assert!(
            count_after_stop >= 2,
            "heartbeat should have fired at least twice"
        );
    }

    #[tokio::test]
    async fn poll_404_surviving_refresh_exits_not_eligible() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        mount_identity_ok(&identity_server, None).await;
        mount_jobs(&api_server, ResponseTemplate::new(404), None).await;

        let exit = tokio::time::timeout(
            Duration::from_secs(10),
            run(
                test_cfg(&api_server, &identity_server),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("run should exit on its own");
        assert_eq!(exit, RunExit::NotEligible);

        let token_requests = count_requests(&identity_server, "POST", "/connect/token").await;
        assert!(
            token_requests >= 2,
            "expected startup plus a forced refresh, got {token_requests} token requests"
        );
    }

    #[tokio::test]
    async fn poll_404_cleared_by_refresh_keeps_polling() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        mount_identity_ok(&identity_server, None).await;
        mount_jobs(&api_server, ResponseTemplate::new(404), Some(1)).await;
        mount_jobs(&api_server, empty_jobs(), None).await;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let cfg = test_cfg(&api_server, &identity_server);
        let handle = tokio::spawn(async move { run(cfg, cancel_clone).await });

        // One 404, the re-poll after the refresh, then at least one more regular tick.
        wait_for_requests(&api_server, "GET", "/access-connectors/rotation/jobs", 3).await;
        assert!(!handle.is_finished(), "a cleared 404 must not end the loop");

        cancel.cancel();
        let exit = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("run should stop on cancel")
            .expect("task panicked");
        assert_eq!(exit, RunExit::Shutdown);
    }

    #[tokio::test]
    async fn poll_404_with_refused_refresh_exits_credential_refused() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        mount_identity_ok(&identity_server, Some(1)).await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"invalid_grant"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&identity_server)
            .await;
        mount_jobs(&api_server, ResponseTemplate::new(404), None).await;

        let exit = tokio::time::timeout(
            Duration::from_secs(10),
            run(
                test_cfg(&api_server, &identity_server),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("run should exit on its own");
        assert_eq!(exit, RunExit::CredentialRefused);
    }

    #[tokio::test]
    async fn claim_with_missing_target_blob_reports_sealed_data_rejected_and_never_executes() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        mount_identity_ok(&identity_server, None).await;

        let job_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();

        // Offer the job once so the claim/reject cycle doesn't repeat.
        mount_jobs(&api_server, jobs(&[(job_id, Uuid::new_v4())]), Some(1)).await;
        mount_jobs(&api_server, empty_jobs(), None).await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job_id}/claim"
            )))
            .respond_with(claim_ok(job_id, attempt_id))
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/failure"
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        let cfg = test_cfg(&api_server, &identity_server);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run(cfg, cancel_clone).await });

        wait_for_requests(&api_server, "POST", "/failure", 1).await;
        cancel.cancel();
        let exit = handle.await.expect("task panicked");
        assert_eq!(exit, RunExit::Shutdown);

        let all_reqs = api_server.received_requests().await.unwrap();

        let cipher_reqs: Vec<_> = all_reqs
            .iter()
            .filter(|r| r.url.path().contains("/cipher"))
            .collect();
        assert!(
            cipher_reqs.is_empty(),
            "no cipher call should happen for a rejected claim: {cipher_reqs:?}"
        );

        let failure_reqs: Vec<_> = all_reqs
            .iter()
            .filter(|r| r.url.path().ends_with("/failure"))
            .collect();
        assert_eq!(failure_reqs.len(), 1, "expected exactly one failure report");
        let body: serde_json::Value =
            serde_json::from_slice(&failure_reqs[0].body).expect("parse failure body");
        assert_eq!(
            body["errorCode"],
            serde_json::json!("sealed_data_rejected"),
            "errorCode must be sealed_data_rejected: {body}"
        );
        assert_eq!(
            body["syncState"],
            serde_json::json!(0),
            "syncState must be 0 (TargetUnchanged): {body}"
        );
    }
}
