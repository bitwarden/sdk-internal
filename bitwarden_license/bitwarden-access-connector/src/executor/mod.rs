//! Rotation job executor: scheduling, retry, and lifecycle management.
//!
//! No socket exists, so a network blip does not close the session; only shutdown does, through
//! `session.close()`.

pub(crate) mod retry;
pub(crate) mod rotation;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_access_token::AccessToken;
use bitwarden_core::Client;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_threading::cancellation_token::CancellationToken;
use retry::RetryCfg;
use rotation::{AbortReason, ExecutionContext, ExecutionResult, execute};
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::{
    api::{RotationApi, build_api_client, models::ApiError},
    auth::session::{SessionLost, SessionManager},
    crypto::AccessConnectorKeyStore,
    integrations::IntegrationRegistry,
    resolver::CredentialResolver,
    sys::SystemEnv,
};

/// Reads the connectivity watch for the last successful server contact. Test-only; the rotation
/// gate reads the channel through `last_ok`.
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
    /// The credential was rejected, by the identity server or a revocation on a connector route;
    /// the operator must reissue it and restart. Startup failures also exit this way.
    CredentialRefused,
    /// The connector is not eligible to use the rotation endpoints. The operator should check the
    /// server configuration.
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
    /// Build an [`AccessConnectorConfig`] for integration tests, bypassing validation such as the
    /// poll-interval minimum. `pub` for `tests/`, hidden from docs.
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

/// Run the connector poll loop until a clean exit condition is reached. A revoked session maps to
/// [`RunExit::CredentialRefused`]; a 404 that survives a refresh probe maps to
/// [`RunExit::NotEligible`].
pub(crate) async fn run(cfg: AccessConnectorConfig, cancel: CancellationToken) -> RunExit {
    let identity_client = match crate::auth::identity::IdentityClient::new(cfg.identity_url.clone())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build identity client: {e}");
            return RunExit::CredentialRefused;
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

    // SessionManager::new backs off internally; the select! lets a cancellation during startup
    // exit cleanly.
    let session = tokio::select! {
        result = crate::auth::session::SessionManager::new(identity_client, cfg.token) => {
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
                    tracing::error!("transient startup error: {e}");
                    return RunExit::CredentialRefused;
                }
            }
        }
        _ = cancel.cancelled() => {
            tracing::info!("shutdown requested during startup; exiting");
            return RunExit::Shutdown;
        }
    };

    let (connectivity_tx, connectivity_rx) = watch::channel(Instant::now());
    let api_client = build_api_client(cfg.api_url.clone(), Arc::clone(&session));
    let api = Arc::new(RotationApi::new(api_client, connectivity_tx));

    // The connector drives its own API calls; this client exists only so rotations can reach
    // the SDK's password generator.
    let sdk_client = Client::new(None);

    let mut registry = IntegrationRegistry::new();

    let custom_script = Arc::new(
        crate::integrations::scripting::custom_script::CustomScriptIntegration::new(
            cfg.script_root.clone(),
            cfg.script_timeout,
            cfg.powershell_path.clone(),
            cfg.powershell_execution_policy.clone(),
            crate::sys::Platform::system(),
            Arc::new(crate::integrations::scripting::ProcessScriptRunner),
        ),
    );
    registry.register(crate::api::models::TargetKind::CustomScript, custom_script);

    let entra = Arc::new(crate::integrations::entra::EntraIntegration::new(
        cfg.entra_verify_probe,
    ));
    registry.register(crate::api::models::TargetKind::Entra, entra);

    let integrations = Arc::new(registry);
    tracing::debug!(
        kinds = ?[
            crate::api::models::TargetKind::CustomScript,
            crate::api::models::TargetKind::Entra,
        ],
        "registered integration kinds"
    );

    let resolver: Arc<dyn CredentialResolver> = Arc::new(
        crate::resolver::config::ConfigCredentialResolver::new(cfg.targets, Arc::new(SystemEnv)),
    );

    let key_store: Arc<AccessConnectorKeyStore> = session.key_store().await;

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

        // Heartbeat: poll the jobs endpoint for the connectivity bump, ignoring the list, until the
        // rotation completes.
        let heartbeat_cancel = cancel.child_token();
        let heartbeat_api = Arc::clone(&api);
        let heartbeat_interval = cfg.heartbeat_interval;
        let heartbeat_handle = tokio::spawn({
            let heartbeat_cancel = heartbeat_cancel.clone();
            async move {
                let mut ticker = interval(heartbeat_interval);
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = heartbeat_cancel.cancelled() => break,
                        _ = ticker.tick() => {
                            tracing::debug!("heartbeat tick");
                            let _ = heartbeat_api.poll_jobs().await;
                        }
                    }
                }
            }
        });

        let exec_ctx = ExecutionContext {
            api: Arc::clone(&api),
            session: Arc::clone(&session),
            integrations: Arc::clone(&integrations),
            resolver: Arc::clone(&resolver),
            generator: sdk_client.generator(),
            key_store: Arc::clone(&key_store),
            retry_cfg: cfg.retry_cfg.clone(),
            offline_grace: cfg.offline_grace,
            last_ok: Arc::clone(&last_ok),
            cancel: cancel.clone(),
        };

        let attempt_id = snap.attempt_id;
        let result = execute(snap, &exec_ctx).await;

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

enum NotEligibleOutcome {
    CredentialRefused,
    NotEligible,
    Retry,
}

/// Probes a `NotEligible` with a forced refresh: a rejected refresh means `CredentialRefused`, and
/// a 404 on the re-poll after a good refresh means `NotEligible`.
async fn handle_not_eligible(session: &SessionManager, api: &RotationApi) -> NotEligibleOutcome {
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
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use tokio::sync::watch;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{
        api::{RotationApi, build_api_client},
        auth::{identity::IdentityClient, session::SessionManager},
        test_support::{encrypted_payload_for, test_token},
    };

    fn identity_ok(bearer: &str, encrypted_payload: &str) -> ResponseTemplate {
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
        SessionManager::new(identity, test_token()).await.unwrap()
    }

    fn make_api(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> (Arc<RotationApi>, watch::Receiver<Instant>) {
        let (tx, rx) = watch::channel(Instant::now());
        let client = build_api_client(api_server.uri(), session);
        let api = Arc::new(RotationApi::new(client, tx));
        (api, rx)
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
        // is_connected reads std::time::Instant, which tokio's virtual time does not advance, so
        // seed an instant already past the grace period.
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

    #[tokio::test]
    async fn single_flight_only_one_claim_per_tick() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, session);

        let job1 = uuid::Uuid::new_v4();
        let job2 = uuid::Uuid::new_v4();

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [
                            {"jobId": job1, "targetSystemId": uuid::Uuid::new_v4()},
                            {"jobId": job2, "targetSystemId": uuid::Uuid::new_v4()}
                        ]
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job1}/claim"
            )))
            .respond_with(ResponseTemplate::new(409))
            .mount(&api_server)
            .await;

        // job1 loses its race, so the loop moves on and stops after claiming job2.
        let attempt_id = uuid::Uuid::new_v4();
        let target_system_id = uuid::Uuid::new_v4();
        let cipher_id = uuid::Uuid::new_v4();
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job2}/claim"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": attempt_id,
                        "jobId": job2,
                        "targetSystemId": target_system_id,
                        "targetSystemName": "test",
                        "kind": 2, // CustomScript
                        "passwordPolicy": {
                            "minLength": 8, "maxLength": 64,
                            "includeUppercase": true, "includeLowercase": true,
                            "includeDigits": true, "includeSymbols": false
                        },
                        "cipherId": cipher_id,
                        "accountIdentity": "user",
                        "terminateSessions": false,
                        "executeBy": execute_by
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let jobs = api.poll_jobs().await.unwrap();
        assert_eq!(jobs.len(), 2);

        // Mirrors the single-flight loop in run().
        let mut claimed = 0;
        let mut snapshot = None;
        for job in &jobs {
            if let Some(s) = api.claim(job.id).await.unwrap() {
                snapshot = Some(s);
                claimed += 1;
                break;
            }
        }

        assert_eq!(claimed, 1);
        assert!(snapshot.is_some());

        let snap = snapshot.unwrap();
        assert_eq!(snap.job_id, job2);

        let all_reqs = api_server.received_requests().await.unwrap();
        let claim_reqs: Vec<_> = all_reqs
            .iter()
            .filter(|r| r.url.path().contains("/claim"))
            .collect();
        assert_eq!(claim_reqs.len(), 2, "should have tried both jobs");
    }

    #[tokio::test]
    async fn heartbeat_fires_during_rotation_then_stops() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, Arc::clone(&session));

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let heartbeat_cancel = CancellationToken::new();
        let heartbeat_api = Arc::clone(&api);
        let heartbeat_interval = Duration::from_millis(20);

        let call_count = Arc::new(Mutex::new(0u32));
        let call_count_clone = Arc::clone(&call_count);

        let heartbeat_handle = tokio::spawn({
            let heartbeat_cancel = heartbeat_cancel.clone();
            async move {
                let mut ticker = interval(heartbeat_interval);
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = heartbeat_cancel.cancelled() => break,
                        _ = ticker.tick() => {
                            let _ = heartbeat_api.poll_jobs().await;
                            *call_count_clone.lock().unwrap() += 1;
                        }
                    }
                }
            }
        });

        // Let the heartbeat fire a few times.
        tokio::time::sleep(Duration::from_millis(70)).await;

        heartbeat_cancel.cancel();
        let _ = heartbeat_handle.await;

        let count_after_stop = *call_count.lock().unwrap();

        // Wait another interval to confirm no new calls.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let count_final = *call_count.lock().unwrap();
        assert_eq!(
            count_after_stop, count_final,
            "no heartbeat calls after cancellation"
        );
        assert!(
            count_after_stop >= 2,
            "heartbeat should have fired at least twice"
        );
    }

    #[test]
    fn run_exit_variants_exist() {
        let _ = RunExit::Shutdown;
        let _ = RunExit::CredentialRefused;
        let _ = RunExit::NotEligible;
    }

    #[tokio::test]
    async fn poll_404_returns_not_eligible() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, session);

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&api_server)
            .await;

        let err = api.poll_jobs().await.unwrap_err();
        assert!(matches!(err, ApiError::NotEligible));
    }
}
