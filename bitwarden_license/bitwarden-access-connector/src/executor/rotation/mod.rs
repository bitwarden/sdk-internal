//! Core rotation execution pipeline.
//!
//! A `Revoked` or `Closed` session fails the attempt up front; an `Expired` one is refreshed by
//! the gate. `execute_by` bounds only the target-side steps (rotate, verify, terminate sessions),
//! not the server-side cipher write and report.

mod cipher;
mod gate;

use std::{sync::Arc, time::Duration};

use bitwarden_core::{Client, OrganizationId};
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_pam::{
    RotationFailureCode, RotationSyncState, SessionTerminationOutcome, VerifiedJob,
};
use bitwarden_threading::cancellation_token::CancellationToken;
use chrono::Utc;
pub(crate) use gate::LastOk;
use gate::{Gate, datetime_to_instant};
use tokio::time::Instant;
use uuid::Uuid;

use super::retry::{GatedOutcome, RetryCfg, with_retries, with_retries_gated};
use crate::{
    api::{AccessConnectorClient, AccessConnectorClientExt as _, models::ApiError},
    auth::session::{SessionLost, SessionManager, SessionPhase},
    error::SafeDetail,
    integrations::{Integration, IntegrationError, IntegrationRegistry, RotateContext},
    resolver::{CredentialResolver, ResolveError},
};

/// Why a gate aborted the rotation without reporting. The server's release sweep reclaims the job.
#[derive(Debug, Clone)]
pub(crate) enum AbortReason {
    /// The claim's `execute_by` deadline has passed.
    LeaseExpired,
    /// The session was revoked or closed.
    SessionLost(SessionLost),
    /// Shutdown was requested.
    Cancelled,
    /// The server no longer knows the attempt (a 404 on an attempt route).
    UnknownAttempt,
    /// The success report could not be delivered.
    ReportFailed,
}

/// Why an attempt stopped before success: report a failure, or abort unreported.
enum Halt {
    Report {
        code: RotationFailureCode,
        detail: Option<SafeDetail>,
        sync: RotationSyncState,
    },
    Abort(AbortReason),
}

impl Halt {
    fn report(code: RotationFailureCode, sync: RotationSyncState) -> Self {
        Self::Report {
            code,
            detail: None,
            sync,
        }
    }

    fn report_detail(
        code: RotationFailureCode,
        detail: SafeDetail,
        sync: RotationSyncState,
    ) -> Self {
        Self::Report {
            code,
            detail: Some(detail),
            sync,
        }
    }
}

impl From<AbortReason> for Halt {
    fn from(reason: AbortReason) -> Self {
        Self::Abort(reason)
    }
}

/// Proof that verify succeeded.
pub(crate) struct Verified(());

/// Proof that the cipher write succeeded.
pub(crate) struct CipherWritten(());

/// The outcome of a single [`execute`] call.
#[derive(Debug)]
pub(crate) enum ExecutionResult {
    /// An outcome was reported to the server.
    Reported,
    /// Aborted before reporting; the server's release sweep reclaims the job.
    Unreported(AbortReason),
}

/// Inputs to [`execute`].
pub(crate) struct ExecutionContext {
    pub(crate) client: Client,
    pub(crate) session: Arc<SessionManager>,
    pub(crate) integrations: Arc<IntegrationRegistry>,
    pub(crate) resolver: Arc<dyn CredentialResolver>,
    /// The organisation that owns the cipher.
    pub(crate) organization_id: OrganizationId,
    pub(crate) retry_cfg: RetryCfg,
    /// How long without server contact before the gate pauses target-side steps.
    pub(crate) offline_grace: Duration,
    /// The instant of the last successful server contact.
    pub(crate) last_ok: LastOk,
    pub(crate) cancel: CancellationToken,
}

/// A gated, target-side integration step.
#[derive(Clone, Copy)]
enum TargetStep {
    Rotate,
    Verify,
    TerminateSessions,
}

impl TargetStep {
    async fn run(
        self,
        integration: &dyn Integration,
        ctx: &RotateContext,
    ) -> Result<(), IntegrationError> {
        match self {
            TargetStep::Rotate => integration.rotate(ctx).await,
            TargetStep::Verify => integration.verify(ctx).await,
            TargetStep::TerminateSessions => integration.terminate_sessions(ctx).await,
        }
    }

    /// The sync state to report when this step fails permanently.
    fn failure_sync(self, err: &IntegrationError) -> RotationSyncState {
        match self {
            TargetStep::Rotate => RotationSyncState::from(err.effect),
            // These run after the target was rotated, so the cipher is now stale.
            TargetStep::Verify | TargetStep::TerminateSessions => RotationSyncState::TargetUpdated,
        }
    }
}

/// One attempt's inputs, shared by its steps.
struct Attempt<'a> {
    job: &'a VerifiedJob,
    ctx: &'a ExecutionContext,
    api: &'a AccessConnectorClient,
    attempt_id: Uuid,
    execute_by: Instant,
}

/// Runs one rotation attempt: a cipher pre-flight check, then resolve, generate, rotate, verify,
/// write cipher, terminate sessions and report.
pub(crate) async fn execute(job: VerifiedJob, ctx: &ExecutionContext) -> ExecutionResult {
    let attempt_id = job.attempt_id();
    let api = ctx.client.access_connector();

    tracing::info!(
        attempt_id = %attempt_id,
        job_id = %job.job_id(),
        cipher_id = %job.cipher_id(),
        target_system_name = %job.target_system_name(),
        "starting rotation execution"
    );

    let attempt = Attempt {
        job: &job,
        ctx,
        api: &api,
        attempt_id,
        execute_by: datetime_to_instant(job.execute_by()),
    };

    match attempt.run().await {
        Ok(()) => ExecutionResult::Reported,
        Err(Halt::Report { code, detail, sync }) => {
            report_failure_absorb(&api, attempt_id, code, detail, sync).await;
            ExecutionResult::Reported
        }
        Err(Halt::Abort(reason)) => ExecutionResult::Unreported(reason),
    }
}

impl Attempt<'_> {
    /// The attempt pipeline; each step returns a [`Halt`] to stop it.
    async fn run(&self) -> Result<(), Halt> {
        let Self {
            job,
            ctx,
            attempt_id,
            ..
        } = *self;

        self.check_session_live().await?;
        self.pre_flight().await?;

        tracing::info!(attempt_id = %attempt_id, "pre-flight cipher check passed");

        let creds = ctx
            .resolver
            .resolve(job.target_system_id(), job.kind())
            .await
            .map_err(|ResolveError::Missing(names)| {
                Halt::report_detail(
                    RotationFailureCode::CredentialsUnresolved,
                    SafeDetail::from_missing_vars(&names),
                    RotationSyncState::TargetUnchanged,
                )
            })?;

        tracing::info!(attempt_id = %attempt_id, "step 1: credentials resolved");

        let new_password = self.generate_password()?;

        tracing::info!(attempt_id = %attempt_id, "step 2: password generated");

        let rotation_started_at = Utc::now();

        let integration = ctx.integrations.get(job.kind()).ok_or_else(|| {
            Halt::report(
                RotationFailureCode::UnsupportedKind,
                RotationSyncState::TargetUnchanged,
            )
        })?;

        let rotate_ctx = RotateContext {
            target_system_id: job.target_system_id(),
            account_identity: job.account_identity().to_owned(),
            new_password,
            creds,
            rotation_started_at,
        };

        self.run_required_step(&*integration, &rotate_ctx, TargetStep::Rotate)
            .await?;

        tracing::info!(
            attempt_id = %attempt_id,
            kind = ?job.kind(),
            "step 3: target rotate succeeded"
        );

        self.run_required_step(&*integration, &rotate_ctx, TargetStep::Verify)
            .await?;

        tracing::info!(attempt_id = %attempt_id, "step 4: verify succeeded");
        let verified = Verified(());

        let cipher_written = self.write_cipher(&rotate_ctx.new_password).await?;

        let termination = self.terminate_sessions(&*integration, &rotate_ctx).await?;

        self.report_success(termination, verified, cipher_written)
            .await?;

        tracing::info!(
            attempt_id = %attempt_id,
            termination = ?termination,
            "step 7: rotation succeeded and reported"
        );
        Ok(())
    }

    /// Fails the attempt up front when the session is terminal.
    async fn check_session_live(&self) -> Result<(), Halt> {
        let phase = self.ctx.session.phase().await;
        if matches!(phase, SessionPhase::Revoked | SessionPhase::Closed) {
            // Best effort: the session is terminal, so the report may fail.
            return Err(Halt::report(
                RotationFailureCode::NoActiveSession,
                RotationSyncState::TargetUnchanged,
            ));
        }
        Ok(())
    }

    /// Generates the new password from the claim's policy.
    fn generate_password(&self) -> Result<String, Halt> {
        let invalid_policy = || {
            Halt::report(
                RotationFailureCode::InvalidPolicy,
                RotationSyncState::TargetUnchanged,
            )
        };
        let gen_req = self.job.generator_request().map_err(|_| invalid_policy())?;
        self.ctx
            .client
            .generator()
            .password(gen_req)
            .map_err(|_| invalid_policy())
    }

    /// Runs one gated target-side step with retries.
    async fn run_target_step(
        &self,
        integration: &dyn Integration,
        rotate_ctx: &RotateContext,
        step: TargetStep,
    ) -> GatedOutcome<(), IntegrationError, AbortReason> {
        let ctx = self.ctx;
        let gate = Gate {
            session: &ctx.session,
            execute_by: self.execute_by,
            offline_grace: ctx.offline_grace,
            last_ok: &*ctx.last_ok,
            cancel: &ctx.cancel,
        };

        with_retries_gated(
            &ctx.retry_cfg,
            || gate.check(),
            || async move {
                step.run(integration, rotate_ctx)
                    .await
                    .map_err(|e| (e.retry, e))
            },
        )
        .await
    }

    /// Runs a step whose failure fails the attempt, reporting the step's sync state.
    async fn run_required_step(
        &self,
        integration: &dyn Integration,
        rotate_ctx: &RotateContext,
        step: TargetStep,
    ) -> Result<(), Halt> {
        match self.run_target_step(integration, rotate_ctx, step).await {
            GatedOutcome::Ok(()) => Ok(()),
            GatedOutcome::Aborted(reason) => Err(reason.into()),
            GatedOutcome::Failed(err) => {
                let sync = step.failure_sync(&err);
                Err(Halt::report_detail(err.code, err.detail, sync))
            }
        }
    }

    /// Ends the account's sessions when the claim asks for it. Termination never fails the
    /// rotation, but a lost session blocks the report.
    async fn terminate_sessions(
        &self,
        integration: &dyn Integration,
        rotate_ctx: &RotateContext,
    ) -> Result<SessionTerminationOutcome, Halt> {
        if !self.job.terminate_sessions() {
            return Ok(SessionTerminationOutcome::NotRequested);
        }

        let attempt_id = self.attempt_id;
        let outcome = self
            .run_target_step(integration, rotate_ctx, TargetStep::TerminateSessions)
            .await;

        Ok(match outcome {
            GatedOutcome::Ok(()) => {
                tracing::info!(attempt_id = %attempt_id, "step 6: session termination succeeded");
                SessionTerminationOutcome::Terminated
            }
            GatedOutcome::Aborted(AbortReason::SessionLost(l)) => {
                return Err(AbortReason::SessionLost(l).into());
            }
            GatedOutcome::Aborted(reason) => {
                // Lease expired or cancelled: report success with term_failed.
                tracing::warn!(
                    attempt_id = %attempt_id,
                    abort_reason = ?reason,
                    "step 6: session termination aborted (reporting term_failed)"
                );
                SessionTerminationOutcome::TermFailed
            }
            GatedOutcome::Failed(err) => {
                tracing::warn!(
                    attempt_id = %attempt_id,
                    "step 6: session termination failed: {err}; reporting term_failed"
                );
                SessionTerminationOutcome::TermFailed
            }
        })
    }

    /// Reports a successful rotation. The proof tokens make skipping verify or the cipher write a
    /// compile error.
    async fn report_success(
        &self,
        termination: SessionTerminationOutcome,
        _verified: Verified,
        _cipher_written: CipherWritten,
    ) -> Result<(), AbortReason> {
        let Self {
            api, attempt_id, ..
        } = *self;
        with_retries(&self.ctx.retry_cfg, None, || async move {
            match api.report_success(attempt_id, termination).await {
                // A 409 or 404 on report is final.
                Err(ApiError::Rejected { .. } | ApiError::UnknownAttempt) => {
                    tracing::warn!(
                        attempt_id = %attempt_id,
                        "success report rejected/unknown by server; treating as reported"
                    );
                    Ok(())
                }
                result => result.map_err(|e| (e.retry_class(), e)),
            }
        })
        .await
        .map_err(|e| match e {
            ApiError::SessionLost(l) => AbortReason::SessionLost(l),
            _ => AbortReason::ReportFailed,
        })
    }
}

/// The abort for an error that ends the attempt unreported, if it is one.
fn abort_from_api(e: &ApiError) -> Option<AbortReason> {
    match e {
        ApiError::UnknownAttempt => Some(AbortReason::UnknownAttempt),
        ApiError::SessionLost(l) => Some(AbortReason::SessionLost(*l)),
        _ => None,
    }
}

/// Maps an API error to a halt: abort when the attempt or session is gone, else report `Internal`.
fn halt_from_api(e: ApiError, sync: RotationSyncState) -> Halt {
    match abort_from_api(&e) {
        Some(reason) => Halt::Abort(reason),
        None => Halt::report(RotationFailureCode::Internal, sync),
    }
}

/// Reports a rotation failure, absorbing report errors. Also used by the claim loop, before an
/// `ExecutionContext` exists.
pub(crate) async fn report_failure_absorb(
    api: &AccessConnectorClient,
    attempt_id: Uuid,
    code: RotationFailureCode,
    detail: Option<SafeDetail>,
    sync_state: RotationSyncState,
) {
    tracing::warn!(
        attempt_id = %attempt_id,
        failure_code = ?code,
        sync_state = ?sync_state,
        detail = detail.as_ref().map(SafeDetail::as_str).unwrap_or(""),
        "rotation failed"
    );
    if let Err(e) = api
        .report_failure(attempt_id, code, detail, sync_state)
        .await
    {
        tracing::warn!(attempt_id = %attempt_id, "failure report itself failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bitwarden_core::key_management::KeySlotIds;
    use bitwarden_crypto::KeyStore;
    use wiremock::ResponseTemplate;

    use super::*;
    use crate::{
        error::Retry,
        integrations::TargetEffect,
        test_support::{
            KEYED_LOGIN_ID, keyed_login_json, mount_identity_ok, test_org_id, test_token,
        },
    };

    struct MockIntegration {
        rotate_result: Result<(), IntegrationError>,
        verify_result: Result<(), IntegrationError>,
        terminate_result: Result<(), IntegrationError>,
        rotate_calls: Arc<Mutex<u32>>,
    }

    impl MockIntegration {
        fn always_ok() -> Self {
            Self {
                rotate_result: Ok(()),
                verify_result: Ok(()),
                terminate_result: Ok(()),
                rotate_calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    #[async_trait]
    impl Integration for MockIntegration {
        async fn rotate(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            *self.rotate_calls.lock().unwrap() += 1;
            replay(&self.rotate_result)
        }

        async fn verify(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            replay(&self.verify_result)
        }

        async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            replay(&self.terminate_result)
        }
    }

    /// A fresh copy of a configured result, since `IntegrationError` is not `Clone`.
    fn replay(r: &Result<(), IntegrationError>) -> Result<(), IntegrationError> {
        r.as_ref().map(|_| ()).map_err(|e| {
            IntegrationError::new(e.retry, e.effect, e.code, SafeDetail::from_kind("mock"))
        })
    }

    /// What a [`Fixture::run`] call observed.
    pub(super) struct Run {
        pub(super) result: ExecutionResult,
        pub(super) rotate_calls: u32,
        requests: Vec<wiremock::Request>,
    }

    impl Run {
        pub(super) fn requests_to(&self, method: &str, suffix: &str) -> Vec<&wiremock::Request> {
            self.requests
                .iter()
                .filter(|r| r.method.as_str() == method && r.url.path().ends_with(suffix))
                .collect()
        }

        pub(super) fn failure_body(&self) -> serde_json::Value {
            let reqs = self.requests_to("POST", "/failure");
            assert_eq!(reqs.len(), 1, "expected exactly one failure report");
            serde_json::from_slice(&reqs[0].body).expect("parse failure body")
        }
    }

    /// One rotation attempt set up against mock servers: the client, an authenticated session, the
    /// execution context and the verified claim. Run it whole with [`Fixture::run`], or take an
    /// [`Attempt`] to drive a single step.
    pub(super) struct Fixture {
        api_server: wiremock::MockServer,
        // Kept alive for the session's token refreshes.
        _identity_server: wiremock::MockServer,
        /// The client's key store, holding the org key the session installed.
        pub(super) store: KeyStore<KeySlotIds>,
        ctx: ExecutionContext,
        job: VerifiedJob,
        api: AccessConnectorClient,
        rotate_calls: Arc<Mutex<u32>>,
    }

    impl Fixture {
        /// A fixture for a claim naming the keyed login, with an always-succeeding integration.
        /// `get` serves every `GET /cipher`; `put` serves `PUT /cipher`.
        pub(super) async fn new(
            get: impl wiremock::Respond + 'static,
            put: impl wiremock::Respond + 'static,
        ) -> Self {
            Self::with_integration(MockIntegration::always_ok(), get, put).await
        }

        /// [`Fixture::new`] against a configured `integ`.
        async fn with_integration(
            integ: MockIntegration,
            get: impl wiremock::Respond + 'static,
            put: impl wiremock::Respond + 'static,
        ) -> Self {
            use bitwarden_pam::WorkSnapshot;
            use bitwarden_pam_sealed::SealedTargetSystemKind;
            use tokio::sync::watch;
            use wiremock::{
                Mock, MockServer,
                matchers::{method, path},
            };

            use crate::{
                api::{REQUEST_TIMEOUT, build_sdk_client},
                auth::identity::IdentityClient,
                resolver::ResolvedCredentials,
                test_support::{sample_config, sample_target, sealed_pair},
            };

            let identity_server = MockServer::start().await;
            let api_server = MockServer::start().await;

            // The session installs the org key the cipher vectors are encrypted under.
            mount_identity_ok(&identity_server, None).await;

            let attempt_id = Uuid::new_v4();
            let job_id = Uuid::new_v4();
            let target_system_id = Uuid::new_v4();

            // The client's key store, which the session installs the org key into.
            let (tx, _rx) = watch::channel(Instant::now());
            let (client, handler) = build_sdk_client(
                api_server.uri(),
                "http://identity.invalid".to_owned(),
                REQUEST_TIMEOUT,
                tx,
            );
            let store = handler.key_store().expect("client key store");
            let identity = IdentityClient::new(identity_server.uri()).unwrap();
            let session = SessionManager::new(identity, test_token(), store.clone())
                .await
                .unwrap();
            handler.set_session(Arc::clone(&session));

            let cipher_path = format!("/access-connectors/rotation/attempts/{attempt_id}/cipher");
            let cipher_id = KEYED_LOGIN_ID;
            Mock::given(method("GET"))
                .and(path(cipher_path.clone()))
                .respond_with(get)
                .mount(&api_server)
                .await;
            Mock::given(method("PUT"))
                .and(path(cipher_path))
                .respond_with(put)
                .mount(&api_server)
                .await;
            for report in ["failure", "success"] {
                Mock::given(method("POST"))
                    .and(path(format!(
                        "/access-connectors/rotation/attempts/{attempt_id}/{report}"
                    )))
                    .respond_with(ResponseTemplate::new(200))
                    .mount(&api_server)
                    .await;
            }

            struct AlwaysOkResolver;
            #[async_trait::async_trait]
            impl CredentialResolver for AlwaysOkResolver {
                async fn resolve(
                    &self,
                    _id: Uuid,
                    _kind: SealedTargetSystemKind,
                ) -> Result<ResolvedCredentials, ResolveError> {
                    Ok(ResolvedCredentials::new())
                }
            }

            let rotate_calls = Arc::clone(&integ.rotate_calls);
            let mut registry = IntegrationRegistry::new();
            registry.register(SealedTargetSystemKind::CustomScript, Arc::new(integ));

            let (target_blob, config_blob) = sealed_pair(
                &store,
                sample_target(target_system_id),
                sample_config(target_system_id, cipher_id),
            );

            let last_ok_time = Arc::new(Mutex::new(Instant::now()));
            let ctx = ExecutionContext {
                client,
                session: Arc::clone(&session),
                integrations: Arc::new(registry),
                resolver: Arc::new(AlwaysOkResolver),
                organization_id: test_org_id(),
                retry_cfg: RetryCfg {
                    max_retry_attempts: 1,
                    retry_base_delay: Duration::from_millis(0),
                },
                offline_grace: Duration::from_secs(60),
                last_ok: Arc::new(move || *last_ok_time.lock().unwrap()),
                cancel: CancellationToken::new(),
            };

            let snapshot = WorkSnapshot {
                attempt_id,
                job_id,
                target_system_id,
                target_system_name: "test".to_owned(),
                cipher_id,
                target_system_sealed_data: Some(target_blob.0),
                target_system_wrapped_key: Some(target_blob.1),
                rotation_config_sealed_data: Some(config_blob.0),
                rotation_config_wrapped_key: Some(config_blob.1),
                execute_by: Utc::now() + chrono::Duration::minutes(5),
            };
            let job = snapshot
                .verify(&store, test_org_id())
                .expect("well-formed claim");
            let api = ctx.client.access_connector();

            Self {
                api_server,
                _identity_server: identity_server,
                store,
                ctx,
                job,
                api,
                rotate_calls,
            }
        }

        /// The attempt, to run a single step against.
        pub(super) fn attempt(&self) -> Attempt<'_> {
            Attempt {
                job: &self.job,
                ctx: &self.ctx,
                api: &self.api,
                attempt_id: self.job.attempt_id(),
                execute_by: datetime_to_instant(self.job.execute_by()),
            }
        }

        /// The requests the API server received with `method` and a path ending in `suffix`.
        pub(super) async fn requests_to(
            &self,
            method: &str,
            suffix: &str,
        ) -> Vec<wiremock::Request> {
            self.api_server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.method.as_str() == method && r.url.path().ends_with(suffix))
                .collect()
        }

        /// Runs the whole pipeline through [`execute`].
        pub(super) async fn run(self) -> Run {
            let result = execute(self.job, &self.ctx).await;
            let rotate_calls = *self.rotate_calls.lock().unwrap();
            Run {
                result,
                rotate_calls,
                requests: self.api_server.received_requests().await.unwrap(),
            }
        }
    }

    pub(super) fn json_response(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(body)
            .insert_header("content-type", "application/json")
    }

    /// Runs a rotation of the cipher served by `get`. The PUT succeeds.
    async fn run_execute(get: ResponseTemplate) -> Run {
        Fixture::new(get, ResponseTemplate::new(200))
            .await
            .run()
            .await
    }

    /// A permanent failure, so no retry waits.
    fn failing(effect: TargetEffect, code: RotationFailureCode) -> IntegrationError {
        IntegrationError::new(
            Retry::Permanent,
            effect,
            code,
            SafeDetail::from_kind("mock"),
        )
    }

    /// Runs a rotation of the keyed login against `integ`, with the cipher PUT succeeding.
    async fn run_with_integration(integ: MockIntegration) -> Run {
        Fixture::with_integration(
            integ,
            json_response(keyed_login_json()),
            ResponseTemplate::new(200),
        )
        .await
        .run()
        .await
    }

    /// A rotation runs every step and reports success once.
    #[tokio::test]
    async fn rotation_succeeds_end_to_end() {
        let run = run_execute(json_response(keyed_login_json())).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 1);
        assert_eq!(run.requests_to("PUT", "/cipher").len(), 1);
        assert_eq!(run.requests_to("POST", "/success").len(), 1);
        assert!(run.requests_to("POST", "/failure").is_empty());
    }

    /// A cipher that fails the pre-flight is reported before any integration call.
    #[tokio::test]
    async fn preflight_cipher_id_mismatch_rejects_before_any_integration_call() {
        let mut json = keyed_login_json();
        json["id"] = Uuid::new_v4().to_string().into();
        let run = run_execute(json_response(json)).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 0, "rotate must not run");
        assert!(run.requests_to("PUT", "/cipher").is_empty());
        assert!(run.requests_to("POST", "/success").is_empty());
        let body = run.failure_body();
        assert_eq!(body["errorCode"], serde_json::json!("sealed_data_rejected"));
        assert_eq!(body["syncState"], serde_json::json!(0));
        assert_eq!(
            body["detail"],
            SafeDetail::from_seal_rejection("pre_flight_cipher_id_mismatch").as_str()
        );
    }

    /// A 404 on the pre-flight `GET /cipher` means the server no longer knows the attempt: abort
    /// without reporting, before the target is touched.
    #[tokio::test]
    async fn preflight_unknown_attempt_aborts_unreported() {
        let run = run_execute(ResponseTemplate::new(404)).await;

        assert!(matches!(
            run.result,
            ExecutionResult::Unreported(AbortReason::UnknownAttempt)
        ));
        assert_eq!(run.rotate_calls, 0, "rotate must not run");
        assert!(run.requests_to("POST", "/failure").is_empty());
        assert!(run.requests_to("POST", "/success").is_empty());
    }

    /// A permanent rotate failure reports the integration's code and the sync state of its effect.
    #[tokio::test]
    async fn rotate_failure_reports_code_and_effect_sync_state() {
        let run = run_with_integration(MockIntegration {
            rotate_result: Err(failing(
                TargetEffect::Unknown,
                RotationFailureCode::ScriptFailed,
            )),
            ..MockIntegration::always_ok()
        })
        .await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 1);
        assert!(run.requests_to("PUT", "/cipher").is_empty());
        assert!(run.requests_to("POST", "/success").is_empty());
        let body = run.failure_body();
        assert_eq!(body["errorCode"], "script_failed");
        assert_eq!(body["syncState"], serde_json::json!(2));
    }

    /// Verify runs after the rotate applied, so its failure is `target_updated` whatever the
    /// effect says.
    #[tokio::test]
    async fn verify_failure_reports_target_updated_ignoring_effect() {
        let run = run_with_integration(MockIntegration {
            verify_result: Err(failing(
                TargetEffect::NotApplied,
                RotationFailureCode::TargetUnreachable,
            )),
            ..MockIntegration::always_ok()
        })
        .await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 1);
        assert!(run.requests_to("PUT", "/cipher").is_empty());
        assert!(run.requests_to("POST", "/success").is_empty());
        let body = run.failure_body();
        assert_eq!(body["errorCode"], "target_unreachable");
        assert_eq!(body["syncState"], serde_json::json!(1));
    }

    /// A failed session termination never fails the rotation: the success report carries
    /// `term_failed` (wire value 2).
    #[tokio::test]
    async fn terminate_sessions_failure_reports_success_with_term_failed() {
        let run = run_with_integration(MockIntegration {
            terminate_result: Err(failing(
                TargetEffect::NotApplied,
                RotationFailureCode::ScriptFailed,
            )),
            ..MockIntegration::always_ok()
        })
        .await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert!(run.requests_to("POST", "/failure").is_empty());
        assert_eq!(run.requests_to("PUT", "/cipher").len(), 1);
        let successes = run.requests_to("POST", "/success");
        assert_eq!(successes.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&successes[0].body).unwrap();
        assert_eq!(body["sessionTermination"], serde_json::json!(2));
    }
}
