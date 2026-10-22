//! Rotation job executor: scheduling, retry, and lifecycle management.
//!
//! No socket exists, so a network blip does not close the session; only shutdown does.

pub(crate) mod retry;
pub(crate) mod rotation;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_access_token::AccessToken;
use bitwarden_core::Client;
use bitwarden_pam::{RotationFailureCode, RotationSyncState};
use bitwarden_threading::cancellation_token::CancellationToken;
use retry::RetryCfg;
use rotation::{AbortReason, ExecutionContext, ExecutionResult, execute};
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::{
    api::{
        AccessConnectorClient, AccessConnectorClientExt as _, REQUEST_TIMEOUT, build_sdk_client,
        models::ApiError,
    },
    auth::session::{SessionLost, SessionManager},
    error::SafeDetail,
    integrations::{
        IntegrationRegistry,
        scripting::{CustomScriptIntegration, PowershellConfig, ProcessScriptRunner},
    },
    resolver::CredentialResolver,
    sys::SystemEnv,
};

/// Reads the connectivity watch. Test-only.
#[cfg(test)]
pub(crate) struct ConnectivityMonitor {
    rx: watch::Receiver<Instant>,
    offline_grace: Duration,
}

#[cfg(test)]
impl ConnectivityMonitor {
    pub(crate) fn new(rx: watch::Receiver<Instant>, offline_grace: Duration) -> Self {
        Self { rx, offline_grace }
    }

    pub(crate) fn last_ok(&self) -> Instant {
        *self.rx.borrow()
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.last_ok().elapsed() <= self.offline_grace
    }
}

/// Why the connector's main loop exited cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunExit {
    /// The cancellation token was cancelled (clean shutdown).
    Shutdown,
    /// The credential was rejected or revoked; the operator must reissue it and restart.
    CredentialRefused,
    /// Startup or authentication failed for a reason other than a refused credential.
    StartupFailed,
    /// The connector is not eligible to use the rotation endpoints.
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
    /// Maximum time without a successful server contact before the gate pauses
    /// target-side steps (default: 60 s).
    pub(crate) offline_grace: Duration,
    pub(crate) retry_cfg: RetryCfg,
    pub(crate) script_root: Option<std::path::PathBuf>,
    /// Script execution timeout for the `CustomScript` integration (default: 60 s).
    pub(crate) script_timeout: Duration,
    /// Explicit PowerShell host path; `None` discovers one on `PATH`.
    pub(crate) powershell_path: Option<std::path::PathBuf>,
    /// `-ExecutionPolicy` value passed to the PowerShell host (default: `Bypass`).
    pub(crate) powershell_execution_policy: String,
    /// Whether to enable the Entra verify probe (ROPC-based; off by default).
    pub(crate) entra_verify_probe: bool,
    /// Per-target credential overrides from the `[targets]` config section.
    pub(crate) targets: std::collections::HashMap<uuid::Uuid, crate::resolver::config::TargetEntry>,
}

impl AccessConnectorConfig {
    /// Builds a config for integration tests, bypassing validation. `pub` for `tests/`.
    #[doc(hidden)]
    pub fn new_for_test(
        api_url: String,
        identity_url: String,
        token: AccessToken,
        poll_interval: Duration,
        script_root: Option<std::path::PathBuf>,
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
            targets: std::collections::HashMap::new(),
        }
    }
}

/// Runs the connector poll loop until a clean exit. A revoked session maps to
/// [`RunExit::CredentialRefused`], other startup failures to [`RunExit::StartupFailed`], and a 404
/// that survives a refresh probe to [`RunExit::NotEligible`].
pub(crate) async fn run(cfg: AccessConnectorConfig, cancel: CancellationToken) -> RunExit {
    let identity_client = match crate::auth::identity::IdentityClient::new(cfg.identity_url.clone())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build identity client: {e}");
            return RunExit::StartupFailed;
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

    // The client owns the key store the session installs the org key into, so it is built first.
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

    // SessionManager::new backs off internally; select! lets cancellation exit cleanly.
    let session = tokio::select! {
        result = crate::auth::session::SessionManager::new(identity_client, cfg.token, key_store) => {
            match result {
                Ok(s) => s,
                Err(crate::auth::session::SessionError::Lost(
                    crate::auth::session::SessionLost::Revoked,
                )) => {
                    tracing::error!(
                        "Access connector credential refused. Have an admin reissue the credential \
                         via ReissueConnectorCredential, then restart the connector with the new \
                         token."
                    );
                    return RunExit::CredentialRefused;
                }
                Err(e) => {
                    // Transient failures outlasting the startup retries; `Lost(Closed)` cannot occur here.
                    tracing::error!("startup authentication failed: {e}");
                    return RunExit::StartupFailed;
                }
            }
        }
        _ = cancel.cancelled() => {
            tracing::info!("shutdown requested during startup; exiting");
            return RunExit::Shutdown;
        }
    };

    handler.set_session(Arc::clone(&session));

    let api = sdk_client.access_connector();

    let mut registry = IntegrationRegistry::new();

    let custom_script = Arc::new(CustomScriptIntegration {
        script_root: cfg.script_root.clone(),
        timeout: cfg.script_timeout,
        powershell: PowershellConfig {
            host: cfg.powershell_path.clone(),
            execution_policy: cfg.powershell_execution_policy.clone(),
        },
        platform: crate::sys::Platform::system(),
        runner: Arc::new(ProcessScriptRunner),
    });
    registry.register(
        bitwarden_pam_sealed::SealedTargetSystemKind::CustomScript,
        custom_script,
    );

    let entra = Arc::new(crate::integrations::entra::EntraIntegration::new(
        cfg.entra_verify_probe,
    ));
    registry.register(bitwarden_pam_sealed::SealedTargetSystemKind::Entra, entra);

    let integrations = Arc::new(registry);
    tracing::debug!(
        kinds = ?[
            bitwarden_pam_sealed::SealedTargetSystemKind::CustomScript,
            bitwarden_pam_sealed::SealedTargetSystemKind::Entra,
        ],
        "registered integration kinds"
    );

    let resolver: Arc<dyn CredentialResolver> = Arc::new(
        crate::resolver::config::ConfigCredentialResolver::new(cfg.targets, Arc::new(SystemEnv)),
    );

    let key_store = session.key_store().await;

    // `SessionManager::new` authenticated eagerly, so the claim has already been read.
    let Some(organization_id) = session.organization_id().await else {
        tracing::error!("access token carries no usable organization claim");
        return RunExit::CredentialRefused;
    };

    let connectivity_rx_for_gate = connectivity_rx.clone();
    let last_ok: Arc<dyn Fn() -> Instant + Send + Sync> =
        Arc::new(move || *connectivity_rx_for_gate.borrow());

    let mut poll_ticker = interval(cfg.poll_interval);
    poll_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut poll_backoff = Duration::from_secs(1);
    let poll_backoff_cap = Duration::from_secs(60);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("shutdown requested; closing session");
                session.close().await;
                return RunExit::Shutdown;
            }
            _ = poll_ticker.tick() => {}
        }

        let jobs = match api.poll_jobs().await {
            Ok(jobs) => {
                poll_backoff = Duration::from_secs(1);
                tracing::debug!(claimable_jobs = jobs.len(), "poll tick");
                jobs
            }
            Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                tracing::error!(
                    "Access connector credential refused (revoked mid-session). Have an admin \
                     reissue the credential via ReissueConnectorCredential, then restart with the \
                     new token."
                );
                return RunExit::CredentialRefused;
            }
            Err(ApiError::NotEligible) => {
                // Probe whether the credential was revoked or only the organization lost access.
                match handle_not_eligible(&session, &api).await {
                    NotEligibleOutcome::CredentialRefused => {
                        return RunExit::CredentialRefused;
                    }
                    NotEligibleOutcome::NotEligible => {
                        tracing::error!(
                            "Access connector not eligible for rotation endpoints. Check: \
                             connector record not revoked or disabled, organisation license \
                             active, UsePam enabled."
                        );
                        return RunExit::NotEligible;
                    }
                    NotEligibleOutcome::Retry => {
                        continue;
                    }
                }
            }
            Err(ApiError::Transient(msg)) => {
                tracing::warn!("transient poll error: {msg}; backing off {poll_backoff:?}");
                tokio::select! {
                    _ = tokio::time::sleep(poll_backoff) => {}
                    _ = cancel.cancelled() => {
                        session.close().await;
                        return RunExit::Shutdown;
                    }
                }
                poll_backoff = (poll_backoff * 2).min(poll_backoff_cap);
                continue;
            }
            Err(e) => {
                tracing::warn!("poll error (non-transient): {e}");
                continue;
            }
        };

        if jobs.is_empty() {
            continue;
        }

        let mut snapshot = None;
        for job in jobs {
            match api.claim(job.id).await {
                Ok(Some(s)) => {
                    tracing::info!(
                        job_id = %s.job_id,
                        target_system_name = %s.target_system_name,
                        "claimed rotation job"
                    );
                    snapshot = Some(s);
                    break; // at most one claim per tick
                }
                Ok(None) => {
                    tracing::debug!(job_id = %job.id, "claim race lost (409); trying next job");
                }
                Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                    tracing::error!(
                        "Access connector credential refused during claim. Reissue credential and \
                         restart."
                    );
                    return RunExit::CredentialRefused;
                }
                Err(ApiError::NotEligible) => {
                    match handle_not_eligible(&session, &api).await {
                        NotEligibleOutcome::CredentialRefused => {
                            return RunExit::CredentialRefused;
                        }
                        NotEligibleOutcome::NotEligible => {
                            return RunExit::NotEligible;
                        }
                        NotEligibleOutcome::Retry => {}
                    }
                    break;
                }
                Err(e) => {
                    tracing::warn!("claim error: {e}");
                    break;
                }
            }
        }

        let Some(snap) = snapshot else {
            continue;
        };

        // Checks 1–7 run first: a rejection never touches the resolver, integration, or cipher
        // route.
        let attempt_id = snap.attempt_id;
        let verified = match snap.verify(&key_store, organization_id) {
            Ok(v) => v,
            Err(rejection) => {
                tracing::warn!(
                    attempt_id = %attempt_id,
                    rejection = rejection.as_str(),
                    "rotation job rejected: sealed data check failed"
                );
                rotation::report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::SealedDataRejected,
                    Some(SafeDetail::from_seal_rejection(rejection.as_str())),
                    RotationSyncState::TargetUnchanged,
                )
                .await;
                continue;
            }
        };

        // Heartbeat until the rotation completes.
        let heartbeat_cancel = cancel.child_token();
        let heartbeat_handle = spawn_heartbeat(
            sdk_client.clone(),
            cfg.heartbeat_interval,
            heartbeat_cancel.clone(),
        );

        let exec_ctx = ExecutionContext {
            client: sdk_client.clone(),
            session: Arc::clone(&session),
            integrations: Arc::clone(&integrations),
            resolver: Arc::clone(&resolver),
            organization_id,
            retry_cfg: cfg.retry_cfg.clone(),
            offline_grace: cfg.offline_grace,
            last_ok: Arc::clone(&last_ok),
            cancel: cancel.clone(),
        };

        let result = execute(verified, &exec_ctx).await;

        heartbeat_cancel.cancel();
        let _ = heartbeat_handle.await;

        match result {
            ExecutionResult::Reported => {
                // rotation.rs already logged the outcome.
                tracing::debug!(attempt_id = %attempt_id, "rotation attempt reported");
            }
            ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Revoked)) => {
                tracing::error!(
                    "Session revoked during rotation; credential refused. Reissue and restart."
                );
                return RunExit::CredentialRefused;
            }
            ExecutionResult::Unreported(reason) => {
                tracing::info!("rotation attempt aborted (unreported): {reason:?}");
            }
        }
    }
}

/// Spawns the heartbeat: polls the jobs endpoint for the connectivity bump until `cancel` fires.
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

enum NotEligibleOutcome {
    CredentialRefused,
    NotEligible,
    Retry,
}

/// Probes a `NotEligible` with a forced refresh: rejected means `CredentialRefused`, a 404 on the
/// re-poll after a good refresh means `NotEligible`.
async fn handle_not_eligible(
    session: &SessionManager,
    api: &AccessConnectorClient,
) -> NotEligibleOutcome {
    // The current bearer is the stale token for force_refresh.
    let stale = match session.bearer(None).await {
        Ok(t) => t,
        Err(crate::auth::session::SessionError::Lost(
            crate::auth::session::SessionLost::Revoked,
        )) => {
            return NotEligibleOutcome::CredentialRefused;
        }
        Err(_) => String::new(),
    };

    match session.force_refresh(&stale, None).await {
        Ok(_) => {}
        Err(crate::auth::session::SessionError::Lost(
            crate::auth::session::SessionLost::Revoked,
        )) => {
            return NotEligibleOutcome::CredentialRefused;
        }
        Err(_) => {
            // Transient refresh failure; keep polling.
            return NotEligibleOutcome::Retry;
        }
    }

    match api.poll_jobs().await {
        Ok(_) => NotEligibleOutcome::Retry,
        Err(ApiError::NotEligible) => NotEligibleOutcome::NotEligible,
        Err(ApiError::SessionLost(SessionLost::Revoked)) => NotEligibleOutcome::CredentialRefused,
        Err(_) => NotEligibleOutcome::Retry,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use tokio::sync::watch;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{
        api::{REQUEST_TIMEOUT, build_sdk_client},
        auth::{identity::IdentityClient, session::SessionManager},
        test_support::{access_token_tagged, encrypted_payload_for, test_org_id, test_token},
    };

    /// Polls until `server` has received a request whose path ends with `suffix`.
    async fn wait_for_request(server: &MockServer, suffix: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let reqs = server.received_requests().await.unwrap();
            if reqs.iter().any(|r| r.url.path().ends_with(suffix)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no request ending with {suffix} arrived within 10s: {reqs:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// `bearer` is a short tag, expanded to a real JWT so the `organization` claim parses.
    fn identity_ok(bearer: &str, encrypted_payload: &str) -> ResponseTemplate {
        let bearer = access_token_tagged(test_org_id(), bearer);
        ResponseTemplate::new(200)
            .set_body_string(format!(
                r#"{{"access_token":"{bearer}","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
            ))
            .insert_header("content-type", "application/json")
    }

    async fn make_session(identity_server: &MockServer, bearer: &str) -> Arc<SessionManager> {
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_ok(bearer, &payload))
            .mount(identity_server)
            .await;

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

    #[test]
    fn connectivity_monitor_fresh_is_connected() {
        let (tx, rx) = watch::channel(Instant::now());
        let monitor = ConnectivityMonitor::new(rx, Duration::from_secs(60));
        assert!(monitor.is_connected());
        drop(tx);
    }

    #[test]
    fn connectivity_monitor_stale_after_offline_grace() {
        // tokio's virtual time does not advance `Instant`, so seed one already past the grace
        // period.
        let stale = Instant::now()
            .checked_sub(Duration::from_secs(61))
            .unwrap_or_else(Instant::now);
        let (tx, rx) = watch::channel(stale);
        let monitor = ConnectivityMonitor::new(rx, Duration::from_secs(60));
        assert!(!monitor.is_connected());
        drop(tx);
    }

    #[test]
    fn connectivity_monitor_bumps_last_ok() {
        let (tx, rx) = watch::channel(Instant::now());
        let monitor = ConnectivityMonitor::new(rx, Duration::from_secs(60));
        let before = monitor.last_ok();
        tx.send_modify(|t| *t = Instant::now());
        let after = monitor.last_ok();
        assert!(after >= before);
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

    #[tokio::test]
    async fn single_flight_only_one_claim_per_tick() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_ok("tok", &payload))
            .mount(&identity_server)
            .await;

        let job1 = uuid::Uuid::new_v4();
        let job2 = uuid::Uuid::new_v4();
        let job3 = uuid::Uuid::new_v4();
        let attempt_id = uuid::Uuid::new_v4();
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();

        // Offer all three jobs once so the claim cycle doesn't repeat.
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [
                            {"jobId": job1, "targetSystemId": uuid::Uuid::new_v4()},
                            {"jobId": job2, "targetSystemId": uuid::Uuid::new_v4()},
                            {"jobId": job3, "targetSystemId": uuid::Uuid::new_v4()}
                        ]
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .up_to_n_times(1)
            .mount(&api_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": attempt_id,
                        "jobId": job2,
                        "targetSystemId": uuid::Uuid::new_v4(),
                        "targetSystemName": "test",
                        "cipherId": uuid::Uuid::new_v4(),
                        "rotationConfigSealedData": "opaque-config-blob",
                        "rotationConfigWrappedKey": "opaque-config-key",
                        "executeBy": execute_by
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        // job3 would also succeed, so claiming it would show the loop did not stop.
        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job3}/claim"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": uuid::Uuid::new_v4(),
                        "jobId": job3,
                        "targetSystemId": uuid::Uuid::new_v4(),
                        "targetSystemName": "test",
                        "cipherId": uuid::Uuid::new_v4(),
                        "rotationConfigSealedData": "opaque-config-blob",
                        "rotationConfigWrappedKey": "opaque-config-key",
                        "executeBy": execute_by
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/failure"
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        let cfg = AccessConnectorConfig::new_for_test(
            api_server.uri(),
            identity_server.uri(),
            test_token(),
            Duration::from_millis(30),
            None,
        );
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run(cfg, cancel_clone).await });

        wait_for_request(&api_server, &format!("/attempts/{attempt_id}/failure")).await;
        cancel.cancel();
        let exit = handle.await.expect("task panicked");
        assert_eq!(exit, RunExit::Shutdown);

        let claims = |job: uuid::Uuid| {
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

        let session = make_session(&identity_server, "tok").await;
        let (client, _rx) = make_client(&api_server, Arc::clone(&session));

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let heartbeat_interval = Duration::from_millis(20);
        let cancel = CancellationToken::new();
        let handle = spawn_heartbeat(client, heartbeat_interval, cancel.clone());

        let deadline = Instant::now() + Duration::from_secs(10);
        while count_requests(&api_server, "GET", "/access-connectors/rotation/jobs").await < 2
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

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
    async fn poll_404_returns_not_eligible() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (client, _rx) = make_client(&api_server, session);

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&api_server)
            .await;

        let err = client.access_connector().poll_jobs().await.unwrap_err();
        assert!(matches!(err, ApiError::NotEligible));
    }

    #[tokio::test]
    async fn claim_with_missing_target_blob_reports_sealed_data_rejected_and_never_executes() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_ok("tok", &payload))
            .mount(&identity_server)
            .await;

        let job_id = uuid::Uuid::new_v4();
        let attempt_id = uuid::Uuid::new_v4();
        let target_system_id = uuid::Uuid::new_v4();
        let cipher_id = uuid::Uuid::new_v4();
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();

        // Offer the job once so the claim/reject cycle doesn't repeat.
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [{"jobId": job_id, "targetSystemId": target_system_id}]
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .up_to_n_times(1)
            .mount(&api_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job_id}/claim"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": attempt_id,
                        "jobId": job_id,
                        "targetSystemId": target_system_id,
                        "targetSystemName": "test",
                        "cipherId": cipher_id,
                        "rotationConfigSealedData": "opaque-config-blob",
                        "rotationConfigWrappedKey": "opaque-config-key",
                        "executeBy": execute_by
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/failure"
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        let cfg = AccessConnectorConfig::new_for_test(
            api_server.uri(),
            identity_server.uri(),
            test_token(),
            Duration::from_millis(30),
            None,
        );
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run(cfg, cancel_clone).await });

        wait_for_request(&api_server, "/failure").await;
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
