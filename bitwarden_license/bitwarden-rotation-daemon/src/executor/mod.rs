//! Rotation job executor: scheduling, retry, and lifecycle management.
//!
//! # ServerConnection poll-model mapping
//!
//! The spec's `ServerConnection` state machine maps onto the poll loop as follows:
//!
//! | Spec state     | Poll-model meaning                                                         |
//! |----------------|----------------------------------------------------------------------------|
//! | `connecting`   | Startup initial `authenticate()` (cancellable — `select!` on cancel token) |
//! | `connected`    | Authenticated and polling; `ConnectivityMonitor.last_ok` is fresh           |
//! | `disconnected` | Server calls failing transiently → exponential backoff (base 1 s, cap 60 s) |
//! | `refused`      | Terminal auth rejection → `RunExit::CredentialRefused`; actionable message   |
//!
//! # Divergences
//!
//! **D1** — `ExecuteRotationWithoutSession`: see `rotation.rs`.
//!
//! **D2** — `ConnectionDropClosesSessions` / `CloseActiveSession` / `CloseIdleSession`:
//! no socket → a network blip does not close the session (bearer kept through
//! `disconnected`).  What the rule protects is held by the singleton `SessionManager`,
//! the gate's connectivity pause, and the `execute_by` fence.  Shutdown maps to
//! `session.close()` → `Closed`.
//!
//! **D4** — `execute_by` gates only target-side steps; server-side cipher write /
//! report continue past it under the transient budget while the session lives.

pub(crate) mod retry;
pub(crate) mod rotation;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

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
    crypto::DaemonKeyStore,
    integrations::IntegrationRegistry,
    resolver::CredentialResolver,
};

// ---------------------------------------------------------------------------
// ConnectivityMonitor (gate arm 5 — not yet wired into the poll loop)
// ---------------------------------------------------------------------------

/// Watches the `connectivity_tx` watch channel and tracks whether the daemon
/// has recently received a successful server response.
///
/// The monitor will be used by the step-boundary gate (arm 5) to detect
/// network partitions: if no successful API call has been received within
/// `offline_grace`, the daemon pauses target-side steps until connectivity
/// recovers or `execute_by` expires.
#[cfg(test)]
pub(crate) struct ConnectivityMonitor {
    rx: watch::Receiver<Instant>,
    offline_grace: Duration,
}

#[cfg(test)]
impl ConnectivityMonitor {
    /// Build a monitor from the receiver side of the connectivity watch channel.
    pub(crate) fn new(rx: watch::Receiver<Instant>, offline_grace: Duration) -> Self {
        Self { rx, offline_grace }
    }

    /// Returns the instant of the last successful server contact.
    pub(crate) fn last_ok(&self) -> Instant {
        *self.rx.borrow()
    }

    /// Returns `true` when the last successful contact is within `offline_grace`.
    pub(crate) fn is_connected(&self) -> bool {
        self.last_ok().elapsed() <= self.offline_grace
    }
}

// ---------------------------------------------------------------------------
// RunExit
// ---------------------------------------------------------------------------

/// The reason the daemon's main loop exited cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunExit {
    /// The cancellation token was cancelled (clean shutdown).
    Shutdown,
    /// The daemon credential was rejected (by the identity server or by a
    /// revocation event on a daemon route).  The operator must reissue the
    /// credential and restart the daemon.
    CredentialRefused,
    /// The daemon is not eligible to use the rotation endpoints (organisation
    /// disabled, license lapsed, or `UsePam` off).  The operator should check
    /// the server configuration.
    NotEligible,
}

// ---------------------------------------------------------------------------
// DaemonConfig  (passed in by the caller — lib.rs / cli.rs)
// ---------------------------------------------------------------------------

/// Configuration for the daemon run loop.
///
/// All durations are validated by the CLI/config layer before this struct is
/// constructed.
pub struct DaemonConfig {
    /// URL of the Bitwarden API server.
    pub(crate) api_url: String,
    /// URL of the Bitwarden identity server.
    pub(crate) identity_url: String,
    /// The parsed daemon access token.
    pub(crate) token: crate::token::DaemonToken,
    /// How often the daemon polls for new jobs (default: 15 s).
    pub(crate) poll_interval: Duration,
    /// How often the heartbeat fires during an executing rotation (default: 30 s).
    pub(crate) heartbeat_interval: Duration,
    /// Maximum time without a successful server contact before the gate pauses
    /// target-side steps (default: 60 s).
    pub(crate) offline_grace: Duration,
    /// Retry configuration for individual rotation steps.
    pub(crate) retry_cfg: RetryCfg,
    /// Optional script root for the `CustomScript` integration.
    pub(crate) script_root: Option<std::path::PathBuf>,
    /// Script execution timeout for the `CustomScript` integration (default: 60 s).
    pub(crate) script_timeout: Duration,
    /// Whether to enable the Entra verify probe (ROPC-based; off by default).
    pub(crate) entra_verify_probe: bool,
    /// Per-target credential overrides from the `[targets]` config section.
    pub(crate) targets: std::collections::HashMap<uuid::Uuid, crate::resolver::config::TargetEntry>,
}

impl DaemonConfig {
    /// Build a [`DaemonConfig`] for integration tests, bypassing the CLI
    /// validation layer (e.g. poll-interval minimum).
    ///
    /// Intentionally `pub` so that integration tests in `tests/` can use it.
    /// The `#[doc(hidden)]` attribute keeps it out of the published docs; the
    /// name signals that this is test infrastructure and must not be used in
    /// production code.
    #[doc(hidden)]
    pub fn new_for_test(
        api_url: String,
        identity_url: String,
        token: crate::token::DaemonToken,
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
            entra_verify_probe: false,
            targets: std::collections::HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// Run the daemon poll loop until a clean exit condition is reached.
///
/// Startup: builds the [`SessionManager`] with capped exponential backoff under
/// a `select!` on `cancel` so that a graceful shutdown can interrupt an
/// in-progress connection attempt.
///
/// Loop: `tokio::time::interval(poll_interval)` with
/// [`MissedTickBehavior::Delay`] (the default `Burst` would violate the
/// `HeartbeatMinInterval SHOULD` after a long inline execution).
///
/// # Credential refused
///
/// On `SessionLost::Revoked` (either during startup or at any point in the
/// loop), the daemon logs an actionable message and returns
/// [`RunExit::CredentialRefused`]:
///
/// > "Daemon credential refused.  Have an admin reissue the credential via
/// > `ReissueDaemonCredential`, then restart the daemon with the new token."
///
/// # Not eligible
///
/// A 404 on the poll route triggers a refresh probe.  If the refresh is
/// rejected → `CredentialRefused`.  If the refresh succeeds but the 404
/// persists → [`RunExit::NotEligible`] with an actionable message:
///
/// > "Daemon not eligible for rotation endpoints.  Check: daemon record not
/// > revoked or disabled, organisation license active, `UsePam` enabled."
pub(crate) async fn run(cfg: DaemonConfig, cancel: CancellationToken) -> RunExit {
    // ── Build session manager (startup / connecting phase) ─────────────────
    let identity_client = match crate::auth::identity::IdentityClient::new(cfg.identity_url.clone())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build identity client: {e}");
            return RunExit::CredentialRefused;
        }
    };

    // Log startup configuration (URLs only — never the token).
    tracing::info!(
        api_url = %cfg.api_url,
        identity_url = %cfg.identity_url,
        poll_interval_secs = cfg.poll_interval.as_secs(),
        heartbeat_interval_secs = cfg.heartbeat_interval.as_secs(),
        configured_targets = cfg.targets.len(),
        "daemon starting"
    );

    // SessionManager::new performs its own backoff internally (up to
    // NO_DEADLINE_MAX_TRIES=3 on transient errors).  We wrap the call in a
    // select! so a cancellation during startup triggers a clean exit.
    let session = tokio::select! {
        result = crate::auth::session::SessionManager::new(identity_client, cfg.token) => {
            match result {
                Ok(s) => s,
                Err(crate::auth::session::SessionError::Lost(
                    crate::auth::session::SessionLost::Revoked,
                )) => {
                    tracing::error!(
                        "Daemon credential refused. Have an admin reissue the credential \
                         via ReissueDaemonCredential, then restart the daemon with the new token."
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

    // ── Build the API client ───────────────────────────────────────────────
    let (connectivity_tx, connectivity_rx) = watch::channel(Instant::now());
    let api_client = build_api_client(cfg.api_url.clone(), Arc::clone(&session));
    let api = Arc::new(RotationApi::new(api_client, connectivity_tx));

    // ── Build the integration registry ────────────────────────────────────
    let mut registry = IntegrationRegistry::new();

    // CustomScript integration.
    let custom_script = Arc::new(
        crate::integrations::custom_script::CustomScriptIntegration::new(
            cfg.script_root.clone(),
            cfg.script_timeout,
        ),
    );
    registry.register(crate::api::models::TargetKind::CustomScript, custom_script);

    // Entra integration (if enabled).
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

    // ── Credential resolver ────────────────────────────────────────────────
    // ConfigCredentialResolver layers config-file overrides on top of env-var fallbacks.
    // When targets is empty the behaviour is identical to the plain EnvCredentialResolver.
    let resolver: Arc<dyn CredentialResolver> = Arc::new(
        crate::resolver::config::ConfigCredentialResolver::new(cfg.targets),
    );

    // ── Key store (shared with session via the session's key_store()) ──────
    let key_store: Arc<DaemonKeyStore> = session.key_store().await;

    // ── Connectivity last_ok closure ───────────────────────────────────────
    let connectivity_rx_for_gate = connectivity_rx.clone();
    let last_ok: Arc<dyn Fn() -> Instant + Send + Sync> =
        Arc::new(move || *connectivity_rx_for_gate.borrow());

    // ── Poll loop ─────────────────────────────────────────────────────────
    let mut poll_ticker = interval(cfg.poll_interval);
    poll_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Transient backoff state for failed polls.
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

        // ── Poll for jobs ──────────────────────────────────────────────────
        let jobs = match api.poll_jobs().await {
            Ok(jobs) => {
                // Reset transient backoff on success.
                poll_backoff = Duration::from_secs(1);
                tracing::debug!(claimable_jobs = jobs.len(), "poll tick");
                jobs
            }
            Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                tracing::error!(
                    "Daemon credential refused (revoked mid-session). Have an admin reissue \
                     the credential via ReissueDaemonCredential, then restart with the new token."
                );
                return RunExit::CredentialRefused;
            }
            Err(ApiError::NotEligible) => {
                // 404 on poll → probe whether this is revocation or org/license issue.
                match handle_not_eligible(&session, &api).await {
                    NotEligibleOutcome::CredentialRefused => {
                        return RunExit::CredentialRefused;
                    }
                    NotEligibleOutcome::NotEligible => {
                        tracing::error!(
                            "Daemon not eligible for rotation endpoints. Check: daemon record \
                             not revoked or disabled, organisation license active, UsePam enabled."
                        );
                        return RunExit::NotEligible;
                    }
                    NotEligibleOutcome::Retry => {
                        // Refresh succeeded but we couldn't immediately confirm eligibility;
                        // continue the loop.
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

        // ── Claim (single-flight: first success wins, then stop) ───────────
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
                    // 409: lost the race; try the next job.
                    tracing::debug!(job_id = %job.id, "claim race lost (409); trying next job");
                }
                Err(ApiError::SessionLost(SessionLost::Revoked)) => {
                    tracing::error!(
                        "Daemon credential refused during claim. Reissue credential and restart."
                    );
                    return RunExit::CredentialRefused;
                }
                Err(ApiError::NotEligible) => {
                    // Eligibility lost during claim; probe like poll_jobs path.
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

        // ── Heartbeat task ─────────────────────────────────────────────────
        // Spawned task polls the jobs endpoint (ignoring the returned list —
        // only the connectivity bump matters).  Cancelled when the rotation
        // completes.
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
                            // Only the connectivity bump matters; ignore the result.
                            tracing::debug!("heartbeat tick");
                            let _ = heartbeat_api.poll_jobs().await;
                        }
                    }
                }
            }
        });

        // ── Execute the rotation (inline) ──────────────────────────────────
        let exec_ctx = ExecutionContext {
            api: Arc::clone(&api),
            session: Arc::clone(&session),
            integrations: Arc::clone(&integrations),
            resolver: Arc::clone(&resolver),
            key_store: Arc::clone(&key_store),
            retry_cfg: cfg.retry_cfg.clone(),
            offline_grace: cfg.offline_grace,
            last_ok: Arc::clone(&last_ok),
            cancel: cancel.clone(),
        };

        let attempt_id = snap.attempt_id;
        let result = execute(snap, &exec_ctx).await;

        // Cancel the heartbeat.
        heartbeat_cancel.cancel();
        let _ = heartbeat_handle.await;

        match result {
            ExecutionResult::Reported => {
                // Outcome was logged per-site in rotation.rs (success → info,
                // failure → warn); this is a lower-level bookkeeping line.
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

// ---------------------------------------------------------------------------
// NotEligible probe
// ---------------------------------------------------------------------------

enum NotEligibleOutcome {
    CredentialRefused,
    NotEligible,
    Retry,
}

/// Handle a `NotEligible` error on the poll or claim path.
///
/// Calls `session.force_refresh` to probe whether this is a revocation (→
/// `CredentialRefused`) or an org/license/config issue (→ `NotEligible`).
async fn handle_not_eligible(session: &SessionManager, api: &RotationApi) -> NotEligibleOutcome {
    // Get the current bearer to use as the stale token for force_refresh.
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
            // Transient refresh failure — may be a connectivity issue; continue polling.
            return NotEligibleOutcome::Retry;
        }
    }

    // Refresh succeeded; try one immediate poll retry.
    match api.poll_jobs().await {
        Ok(_) => NotEligibleOutcome::Retry,
        Err(ApiError::NotEligible) => NotEligibleOutcome::NotEligible,
        Err(ApiError::SessionLost(SessionLost::Revoked)) => NotEligibleOutcome::CredentialRefused,
        Err(_) => NotEligibleOutcome::Retry,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        token::DaemonToken,
    };

    const VALID_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn test_token() -> DaemonToken {
        use std::str::FromStr;
        DaemonToken::from_str(VALID_TOKEN_STR).unwrap()
    }

    fn token_encryption_key() -> bitwarden_crypto::SymmetricCryptoKey {
        use bitwarden_crypto::{SymmetricCryptoKey, derive_shareable_key};
        use bitwarden_encoding::B64;
        use zeroize::Zeroizing;
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().unwrap();
        let key_bytes: Zeroizing<[u8; 16]> = Zeroizing::new(b64.as_bytes().try_into().unwrap());
        SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            key_bytes,
            "accesstoken",
            Some("sm-access-token"),
        ))
    }

    fn make_encrypted_payload(
        token_key: &bitwarden_crypto::SymmetricCryptoKey,
        org_key: &bitwarden_crypto::SymmetricCryptoKey,
    ) -> String {
        use bitwarden_crypto::KeyEncryptable;
        let org_key_bytes = org_key.to_encoded();
        let b64_str: String = bitwarden_encoding::B64::from(org_key_bytes.as_ref()).into();
        let payload_json = format!(r#"{{"encryptionKey":"{b64_str}"}}"#);
        payload_json
            .as_str()
            .encrypt_with_key(token_key)
            .unwrap()
            .to_string()
    }

    fn identity_ok(bearer: &str, encrypted_payload: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_string(format!(
                r#"{{"access_token":"{bearer}","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
            ))
            .insert_header("content-type", "application/json")
    }

    async fn make_session(identity_server: &MockServer, bearer: &str) -> Arc<SessionManager> {
        let token_key = token_encryption_key();
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = make_encrypted_payload(&token_key, &org_key);

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

    // ── ConnectivityMonitor ────────────────────────────────────────────────

    #[test]
    fn connectivity_monitor_fresh_is_connected() {
        let (tx, rx) = watch::channel(Instant::now());
        let monitor = ConnectivityMonitor::new(rx, Duration::from_secs(60));
        assert!(monitor.is_connected());
        drop(tx);
    }

    #[test]
    fn connectivity_monitor_stale_after_offline_grace() {
        // Seed the channel with an Instant that is already 61 s in the past.
        // `ConnectivityMonitor::is_connected` uses `std::time::Instant::elapsed`
        // (wall-clock), so we cannot rely on tokio's virtual time.
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
        // Bump the channel.
        tx.send_modify(|t| *t = Instant::now());
        let after = monitor.last_ok();
        assert!(after >= before);
    }

    // ── Single-flight: poll returns 2 jobs, exactly 1 claim ───────────────

    #[tokio::test]
    async fn single_flight_only_one_claim_per_tick() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, session);

        let job1 = uuid::Uuid::new_v4();
        let job2 = uuid::Uuid::new_v4();

        // Poll returns 2 jobs.
        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
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

        // First claim (job1) returns 409.
        Mock::given(method("POST"))
            .and(path(format!("/rotation/jobs/{job1}/claim")))
            .respond_with(ResponseTemplate::new(409))
            .mount(&api_server)
            .await;

        // Second claim (job2) would succeed, but single-flight: we only stop
        // after the first success. Here we verify that if job1 fails (409) the
        // loop continues to job2 but stops after claiming it.
        let attempt_id = uuid::Uuid::new_v4();
        let target_system_id = uuid::Uuid::new_v4();
        let cipher_id = uuid::Uuid::new_v4();
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();

        Mock::given(method("POST"))
            .and(path(format!("/rotation/jobs/{job2}/claim")))
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

        // Poll.
        let jobs = api.poll_jobs().await.unwrap();
        assert_eq!(jobs.len(), 2);

        // Simulate single-flight: iterate, claim until first success.
        let mut claimed = 0;
        let mut snapshot = None;
        for job in &jobs {
            if let Some(s) = api.claim(job.id).await.unwrap() {
                snapshot = Some(s);
                claimed += 1;
                break;
            }
        }

        // Exactly one claim succeeded.
        assert_eq!(claimed, 1);
        assert!(snapshot.is_some());

        // Verify that job2 was claimed (job1 was 409).
        let snap = snapshot.unwrap();
        assert_eq!(snap.job_id, job2);

        // Verify we only made 2 claim requests total (job1=409, job2=200).
        let all_reqs = api_server.received_requests().await.unwrap();
        let claim_reqs: Vec<_> = all_reqs
            .iter()
            .filter(|r| r.url.path().contains("/claim"))
            .collect();
        assert_eq!(claim_reqs.len(), 2, "should have tried both jobs");
    }

    // ── Heartbeat stops after rotation completes ───────────────────────────

    #[tokio::test]
    async fn heartbeat_fires_during_rotation_then_stops() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, Arc::clone(&session));

        // Mount a catch-all for /rotation/daemon/jobs (heartbeat calls).
        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
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

        // Stop the heartbeat.
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

    // ── RunExit variants exist ────────────────────────────────────────────

    #[test]
    fn run_exit_variants_exist() {
        let _ = RunExit::Shutdown;
        let _ = RunExit::CredentialRefused;
        let _ = RunExit::NotEligible;
    }

    // ── Poll 404 → NotEligible classification ─────────────────────────────

    #[tokio::test]
    async fn poll_404_returns_not_eligible() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "tok").await;
        let (api, _rx) = make_api(&api_server, session);

        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&api_server)
            .await;

        let err = api.poll_jobs().await.unwrap_err();
        assert!(matches!(err, ApiError::NotEligible));
    }
}
