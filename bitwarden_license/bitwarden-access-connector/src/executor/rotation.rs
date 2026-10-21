//! Core rotation execution pipeline.
//!
//! A `Revoked` or `Closed` session fails the attempt up front; an `Expired` one is refreshed by
//! the gate. `execute_by` bounds only target-side steps (3, 4, 6), not server-side 5 and 7.
//!
//! The cipher goes through the vault's typed path: decrypt, replace only the login password
//! (the old one moves into history), re-encrypt. Non-login, foreign-organization and restricted
//! ciphers are never rotated.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_core::{Client, OrganizationId};
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_pam::{
    RotationCipherError, RotationFailureCode, RotationSyncState, SessionTerminationOutcome,
    VerifiedJob, rotate_cipher_password,
};
use bitwarden_vault::Cipher;
use chrono::Utc;

use super::retry::{GatedOutcome, RetryCfg, with_retries, with_retries_gated};
use crate::{
    api::{AccessConnectorClient, AccessConnectorClientExt as _, models::ApiError},
    auth::session::{SessionLost, SessionManager, SessionPhase},
    error::{ErrorClass, SafeDetail},
    integrations::{Integration, IntegrationRegistry, RotateContext},
    resolver::{CredentialResolver, ResolveError},
};

/// Why a step-boundary gate aborted the rotation, unreported; the server's release sweep reclaims
/// it.
#[derive(Debug, Clone)]
pub(crate) enum AbortReason {
    /// The claim's `execute_by` lease deadline has passed.
    LeaseExpired,
    /// The session was terminally lost (revoked or closed).
    SessionLost(SessionLost),
    /// The `CancellationToken` was cancelled (shutdown).
    Cancelled,
}

/// Proof that step 4 (verify) succeeded.
pub(crate) struct Verified(());

/// Proof that step 5 (cipher write) succeeded.
pub(crate) struct CipherWritten(());

/// The outcome of a single [`execute`] call.
#[derive(Debug)]
pub(crate) enum ExecutionResult {
    /// An outcome (success or failure) was reported to the server.
    Reported,
    /// Aborted before an outcome could be reported; the server's release sweep reclaims the job.
    Unreported(AbortReason),
}

/// Inputs to [`execute`].
pub(crate) struct ExecutionContext {
    pub(crate) client: Client,
    pub(crate) session: Arc<SessionManager>,
    pub(crate) integrations: Arc<IntegrationRegistry>,
    pub(crate) resolver: Arc<dyn CredentialResolver>,
    /// The organisation whose key the cipher is encrypted under.
    pub(crate) organization_id: OrganizationId,
    pub(crate) retry_cfg: RetryCfg,
    /// How long without a successful server contact before the gate pauses target-side steps.
    pub(crate) offline_grace: Duration,
    /// Returns the instant of the last successful server contact.
    pub(crate) last_ok: Arc<dyn Fn() -> Instant + Send + Sync>,
    pub(crate) cancel: bitwarden_threading::cancellation_token::CancellationToken,
}

/// Runs one rotation attempt: pre-flight cipher check (check 8), then the seven steps: resolve,
/// generate, rotate, verify, write cipher, terminate sessions, report.
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

    {
        let phase = ctx.session.phase().await;
        if matches!(phase, SessionPhase::Revoked | SessionPhase::Closed) {
            // Best-effort failure report: session is terminal, report may fail.
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::NoActiveSession,
                None,
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    }

    // Check 8: runs before the target is touched, so an unrotatable cipher (wrong organization or
    // type, restricted, undecryptable) fails as target_unchanged. Step 5 repeats it.
    {
        let cipher = match fetch_cipher(&api, &ctx.retry_cfg, attempt_id).await {
            Ok(c) => c,
            Err(ApiError::UnknownAttempt) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Closed));
            }
            Err(ApiError::SessionLost(l)) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(l));
            }
            Err(_) => {
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::Internal,
                    None,
                    RotationSyncState::TargetUnchanged,
                )
                .await;
                return ExecutionResult::Reported;
            }
        };

        if cipher.id.map(uuid::Uuid::from) != Some(job.cipher_id()) {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::SealedDataRejected,
                Some(SafeDetail::from_seal_rejection(
                    "pre_flight_cipher_id_mismatch",
                )),
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }

        // A dry run of the write in step 5: the new password does not exist yet, so a placeholder
        // stands in, and the request is discarded. Only the verdict matters here.
        if let Err(e) = rotate_cipher_password(
            &api.key_store,
            ctx.organization_id,
            cipher,
            PRE_FLIGHT_PLACEHOLDER_PASSWORD,
        ) {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::SealedDataRejected,
                Some(SafeDetail::from_seal_rejection(cipher_rejection_reason(
                    &e, true,
                ))),
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    }

    tracing::info!(attempt_id = %attempt_id, "check 8: pre-flight cipher read succeeded");

    let execute_by_instant = datetime_to_instant(job.execute_by());

    let creds = match ctx
        .resolver
        .resolve(job.target_system_id(), job.kind())
        .await
    {
        Ok(c) => c,
        Err(ResolveError::Missing(names)) => {
            let detail = SafeDetail::from_missing_vars(&names);
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::CredentialsUnresolved,
                Some(detail),
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    tracing::info!(attempt_id = %attempt_id, "step 1: credentials resolved");

    let gen_req = match job.generator_request() {
        Ok(r) => r,
        Err(_) => {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::InvalidPolicy,
                None,
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    let new_password = match ctx.client.generator().password(gen_req) {
        Ok(p) => zeroize::Zeroizing::new(p),
        Err(_) => {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::InvalidPolicy,
                None,
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    tracing::info!(attempt_id = %attempt_id, "step 2: password generated");

    let rotation_started_at = Utc::now();

    let integration: Arc<dyn Integration> = match ctx.integrations.get(job.kind()) {
        Some(i) => i,
        None => {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::UnsupportedKind,
                None,
                RotationSyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    let rotate_ctx = Arc::new(RotateContext {
        target_system_id: job.target_system_id(),
        account_identity: job.account_identity().to_owned(),
        new_password: new_password.clone(),
        creds,
        rotation_started_at,
    });

    {
        let gate = make_gate(
            Arc::clone(&ctx.session),
            execute_by_instant,
            ctx.offline_grace,
            Arc::clone(&ctx.last_ok),
            ctx.cancel.clone(),
        );

        let integration = Arc::clone(&integration);
        let rotate_ctx_ref = Arc::clone(&rotate_ctx);
        let outcome = with_retries_gated(&ctx.retry_cfg, gate, || {
            let integration = Arc::clone(&integration);
            let rotate_ctx_ref = Arc::clone(&rotate_ctx_ref);
            async move {
                match integration.rotate(&rotate_ctx_ref).await {
                    Ok(()) => Ok(()),
                    Err(e) => Err((e.class, e)),
                }
            }
        })
        .await;

        match outcome {
            GatedOutcome::Ok(()) => {
                tracing::info!(
                    attempt_id = %attempt_id,
                    kind = ?job.kind(),
                    "step 3: target rotate succeeded"
                );
            }
            GatedOutcome::Aborted(reason) => {
                return ExecutionResult::Unreported(reason);
            }
            GatedOutcome::Failed(err) => {
                let sync_state = RotationSyncState::from(err.effect);
                report_failure_absorb(&api, attempt_id, err.code, Some(err.detail), sync_state)
                    .await;
                return ExecutionResult::Reported;
            }
        }
    }

    let verified = {
        let gate = make_gate(
            Arc::clone(&ctx.session),
            execute_by_instant,
            ctx.offline_grace,
            Arc::clone(&ctx.last_ok),
            ctx.cancel.clone(),
        );

        let integration = Arc::clone(&integration);
        let rotate_ctx_ref = Arc::clone(&rotate_ctx);
        let outcome = with_retries_gated(&ctx.retry_cfg, gate, || {
            let integration = Arc::clone(&integration);
            let rotate_ctx_ref = Arc::clone(&rotate_ctx_ref);
            async move {
                match integration.verify(&rotate_ctx_ref).await {
                    Ok(()) => Ok(()),
                    Err(e) => Err((e.class, e)),
                }
            }
        })
        .await;

        match outcome {
            GatedOutcome::Ok(()) => {
                tracing::info!(attempt_id = %attempt_id, "step 4: verify succeeded");
                Verified(())
            }
            GatedOutcome::Aborted(reason) => {
                return ExecutionResult::Unreported(reason);
            }
            GatedOutcome::Failed(err) => {
                // The rotation applied but the vault was not written.
                report_failure_absorb(
                    &api,
                    attempt_id,
                    err.code,
                    Some(err.detail),
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        }
    };

    // execute_by does not bound this step; the session's bearer refresh handles token expiry.
    let cipher_written = {
        let cipher = match fetch_cipher(&api, &ctx.retry_cfg, attempt_id).await {
            Ok(c) => c,
            Err(ApiError::UnknownAttempt) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Closed));
            }
            Err(ApiError::SessionLost(l)) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(l));
            }
            Err(_) => {
                // Step 3 already changed the target credential, so report target_updated.
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::Internal,
                    None,
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        };

        // Check 8, repeated: the target is already rotated, so this fails as target_updated.
        if cipher.id.map(uuid::Uuid::from) != Some(job.cipher_id()) {
            report_failure_absorb(
                &api,
                attempt_id,
                RotationFailureCode::SealedDataRejected,
                Some(SafeDetail::from_seal_rejection(
                    "pre_write_cipher_id_mismatch",
                )),
                RotationSyncState::TargetUpdated,
            )
            .await;
            return ExecutionResult::Reported;
        }

        tracing::debug!(attempt_id = %attempt_id, cipher_id = %job.cipher_id(), "cipher fetched");

        let request = match rotate_cipher_password(
            &api.key_store,
            ctx.organization_id,
            cipher,
            &new_password,
        ) {
            Ok(r) => r,
            // The vault re-encrypted the cipher, but the request built from it is unusable.
            Err(RotationCipherError::CipherDataPresent | RotationCipherError::Json(_)) => {
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::CipherEncryptFailed,
                    None,
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
            // A `Crypto` error cannot be split into decrypt vs encrypt; the pre-flight dry run
            // already exercised encryption, so treat it as a rejected cipher.
            Err(e) => {
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::SealedDataRejected,
                    Some(SafeDetail::from_seal_rejection(cipher_rejection_reason(
                        &e, false,
                    ))),
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        };

        let result = with_retries(
            &ctx.retry_cfg,
            None, // no deadline
            || {
                let api = &api;
                let request = request.clone();
                async move {
                    match api.put_cipher(attempt_id, request).await {
                        Ok(()) => Ok(()),
                        Err(ApiError::Transient(s)) => {
                            Err((ErrorClass::Transient, ApiError::Transient(s)))
                        }
                        Err(ApiError::SessionLost(l)) => {
                            Err((ErrorClass::Fatal, ApiError::SessionLost(l)))
                        }
                        Err(e) => Err((ErrorClass::Fatal, e)),
                    }
                }
            },
        )
        .await;

        match result {
            Ok(()) => {
                tracing::info!(
                    attempt_id = %attempt_id,
                    cipher_id = %job.cipher_id(),
                    "step 5: cipher written"
                );
                CipherWritten(())
            }
            Err(ApiError::Rejected { .. }) => {
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::CipherWriteRejected,
                    None,
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
            Err(ApiError::UnknownAttempt) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Closed));
            }
            Err(ApiError::SessionLost(l)) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(l));
            }
            Err(_) => {
                // The target credential already changed, so report target_updated.
                report_failure_absorb(
                    &api,
                    attempt_id,
                    RotationFailureCode::Internal,
                    None,
                    RotationSyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        }
    };

    // Termination never fails the rotation, but a lost session blocks the success report.
    let termination_result: SessionTerminationOutcome = if !job.terminate_sessions() {
        SessionTerminationOutcome::NotRequested
    } else {
        let gate = make_gate(
            Arc::clone(&ctx.session),
            execute_by_instant,
            ctx.offline_grace,
            Arc::clone(&ctx.last_ok),
            ctx.cancel.clone(),
        );

        let integration = Arc::clone(&integration);
        let rotate_ctx_ref = Arc::clone(&rotate_ctx);
        let outcome = with_retries_gated(&ctx.retry_cfg, gate, || {
            let integration = Arc::clone(&integration);
            let rotate_ctx_ref = Arc::clone(&rotate_ctx_ref);
            async move {
                match integration.terminate_sessions(&rotate_ctx_ref).await {
                    Ok(()) => Ok(()),
                    Err(e) => Err((e.class, e)),
                }
            }
        })
        .await;

        match outcome {
            GatedOutcome::Ok(()) => {
                tracing::info!(attempt_id = %attempt_id, "step 6: session termination succeeded");
                SessionTerminationOutcome::Terminated
            }
            GatedOutcome::Aborted(AbortReason::SessionLost(l)) => {
                return ExecutionResult::Unreported(AbortReason::SessionLost(l));
            }
            GatedOutcome::Aborted(reason) => {
                // Lease expired or cancelled during termination: report success with term_failed.
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
        }
    };

    let termination = termination_result;
    let report_result = report_success_inner(
        &api,
        &ctx.retry_cfg,
        attempt_id,
        termination,
        verified,
        cipher_written,
    )
    .await;

    match report_result {
        Ok(()) => {
            tracing::info!(
                attempt_id = %attempt_id,
                termination = ?termination,
                "step 7: rotation succeeded and reported"
            );
            ExecutionResult::Reported
        }
        Err(ApiError::SessionLost(l)) => ExecutionResult::Unreported(AbortReason::SessionLost(l)),
        Err(_) => ExecutionResult::Unreported(AbortReason::SessionLost(SessionLost::Closed)),
    }
}

/// Reports a successful rotation. The proof tokens are module-private, so skipping step 4 or 5 is a
/// compile error.
async fn report_success_inner(
    api: &AccessConnectorClient,
    retry_cfg: &super::retry::RetryCfg,
    attempt_id: uuid::Uuid,
    termination: SessionTerminationOutcome,
    _verified: Verified,
    _cipher_written: CipherWritten,
) -> Result<(), ApiError> {
    with_retries(retry_cfg, None, || {
        let api_ref = api;
        async move {
            match api_ref.report_success(attempt_id, termination).await {
                Ok(()) => Ok(()),
                Err(ApiError::Transient(s)) => Err((ErrorClass::Transient, ApiError::Transient(s))),
                Err(ApiError::SessionLost(l)) => Err((ErrorClass::Fatal, ApiError::SessionLost(l))),
                // 409/404 on report is final; treat as reported.
                Err(ApiError::Rejected { .. }) | Err(ApiError::UnknownAttempt) => {
                    tracing::warn!(
                        attempt_id = %attempt_id,
                        "success report rejected/unknown by server; treating as reported"
                    );
                    Ok(())
                }
                Err(e) => Err((ErrorClass::Fatal, ApiError::Transient(e.to_string()))),
            }
        }
    })
    .await
}

/// Builds the gate for the gated-retry steps (3, 4, 6): lease expiry, cancellation, session loss,
/// and pauses for re-authentication or stale connectivity.
fn make_gate(
    session: Arc<SessionManager>,
    execute_by: Instant,
    offline_grace: Duration,
    last_ok: Arc<dyn Fn() -> Instant + Send + Sync>,
    cancel: bitwarden_threading::cancellation_token::CancellationToken,
) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<(), AbortReason>> + Send>> {
    move || {
        let session = Arc::clone(&session);
        let last_ok = Arc::clone(&last_ok);
        let cancel = cancel.clone();

        Box::pin(async move {
            loop {
                // Arm 1: lease expired.
                if Instant::now() >= execute_by {
                    return Err(AbortReason::LeaseExpired);
                }

                // Arm 2: cancelled.
                if cancel.is_cancelled() {
                    return Err(AbortReason::Cancelled);
                }

                let phase = session.phase().await;

                // Arm 3: terminal session.
                match phase {
                    SessionPhase::Revoked => {
                        return Err(AbortReason::SessionLost(SessionLost::Revoked));
                    }
                    SessionPhase::Closed => {
                        return Err(AbortReason::SessionLost(SessionLost::Closed));
                    }
                    _ => {}
                }

                // Arm 4: expired/authenticating → pause waiting for refresh.
                if matches!(phase, SessionPhase::Expired | SessionPhase::Authenticating) {
                    // bearer() renews the token, bounded by execute_by.
                    match session.bearer(Some(execute_by)).await {
                        Ok(_) => {
                            continue;
                        }
                        Err(crate::auth::session::SessionError::Lost(l)) => {
                            return Err(AbortReason::SessionLost(l));
                        }
                        Err(crate::auth::session::SessionError::Transient(_)) => {
                            // Transient renewal failure up to deadline → LeaseExpired.
                            return Err(AbortReason::LeaseExpired);
                        }
                    }
                }

                // Arm 5: active but connectivity stale.
                if phase == SessionPhase::Active {
                    let stale = (last_ok)();
                    if stale.elapsed() > offline_grace {
                        // Poll every second until connectivity recovers, execute_by passes, or
                        // shutdown is requested.
                        loop {
                            if Instant::now() >= execute_by {
                                return Err(AbortReason::LeaseExpired);
                            }
                            if cancel.is_cancelled() {
                                return Err(AbortReason::Cancelled);
                            }
                            let fresh = (last_ok)();
                            if fresh.elapsed() <= offline_grace {
                                break;
                            }
                            let remaining = execute_by.saturating_duration_since(Instant::now());
                            let sleep = Duration::from_secs(1).min(remaining);
                            if sleep == Duration::ZERO {
                                return Err(AbortReason::LeaseExpired);
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(sleep) => {}
                                _ = cancel.cancelled() => {
                                    return Err(AbortReason::Cancelled);
                                }
                            }
                        }
                        continue;
                    }
                }

                return Ok(());
            }
        })
    }
}

/// Converts a UTC `DateTime` to an [`std::time::Instant`]; past maps to now, far future caps at
/// `now + 24h`.
fn datetime_to_instant(dt: chrono::DateTime<chrono::Utc>) -> Instant {
    use chrono::Utc;
    let now_utc = Utc::now();
    let delta = dt - now_utc;
    let mono_now = Instant::now();

    if delta.num_seconds() <= 0 {
        mono_now
    } else {
        let secs = delta.num_seconds().min(86400) as u64;
        mono_now + Duration::from_secs(secs)
    }
}

/// Fetches the cipher with retries. Callers handle failure: check 8 and step 5 report different
/// sync states.
async fn fetch_cipher(
    api: &AccessConnectorClient,
    retry_cfg: &RetryCfg,
    attempt_id: uuid::Uuid,
) -> Result<Cipher, ApiError> {
    with_retries(retry_cfg, None, move || async move {
        match api.get_cipher(attempt_id).await {
            Ok(c) => Ok(c),
            Err(ApiError::Transient(s)) => Err((ErrorClass::Transient, ApiError::Transient(s))),
            Err(ApiError::SessionLost(l)) => Err((ErrorClass::Fatal, ApiError::SessionLost(l))),
            Err(e) => Err((ErrorClass::Fatal, e)),
        }
    })
    .await
}

/// Stands in for the new password in the pre-flight dry run of the cipher write.
const PRE_FLIGHT_PLACEHOLDER_PASSWORD: &str = "pre-flight-placeholder";

/// A fixed, content-free reason for a rejected cipher, for the failure report.
fn cipher_rejection_reason(err: &RotationCipherError, pre_flight: bool) -> &'static str {
    match (err, pre_flight) {
        (RotationCipherError::CipherOrganizationMismatch, true) => "pre_flight_cipher_org_mismatch",
        (RotationCipherError::CipherOrganizationMismatch, false) => "pre_write_cipher_org_mismatch",
        (RotationCipherError::CipherNotLogin, true) => "pre_flight_cipher_not_login",
        (RotationCipherError::CipherNotLogin, false) => "pre_write_cipher_not_login",
        (RotationCipherError::CipherRestricted, true) => "pre_flight_cipher_restricted",
        (RotationCipherError::CipherRestricted, false) => "pre_write_cipher_restricted",
        (RotationCipherError::CipherWithoutItemKey, true) => "pre_flight_cipher_without_item_key",
        (RotationCipherError::CipherWithoutItemKey, false) => "pre_write_cipher_without_item_key",
        (RotationCipherError::CipherDataPresent | RotationCipherError::Json(_), true) => {
            "pre_flight_cipher_write_invalid"
        }
        (_, true) => "pre_flight_cipher_decrypt_failed",
        (_, false) => "pre_write_cipher_decrypt_failed",
    }
}

/// Reports a rotation failure, absorbing report errors (still `Reported`). `pub(crate)` so the
/// claim loop can report a `verify` rejection before an `ExecutionContext` exists.
pub(crate) async fn report_failure_absorb(
    api: &AccessConnectorClient,
    attempt_id: uuid::Uuid,
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

// Used in make_gate's return type.
use std::future::Future;

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use bitwarden_core::key_management::KeySlotIds;
    use bitwarden_crypto::KeyStore;
    use wiremock::ResponseTemplate;

    use super::*;
    use crate::{
        error::SafeDetail,
        integrations::{Integration, IntegrationError, RotateContext, TargetEffect},
        resolver::ResolvedCredentials,
        test_support::{
            KEYED_LOGIN_ID, KEYED_LOGIN_WITH_ATTACHMENT, KEYED_LOGIN_WITH_ATTACHMENT_ID,
            KEYLESS_LOGIN, KEYLESS_LOGIN_ID, RESTRICTED_LOGIN, RESTRICTED_LOGIN_ID,
            access_token_tagged, encrypted_payload_for, keyed_login_json, test_org_id, test_token,
            vector_json,
        },
    };

    /// An identity success body whose access token carries the `organization` claim.
    fn identity_ok_body(encrypted_payload: &str) -> String {
        let access_token = access_token_tagged(test_org_id(), "tok");
        format!(
            r#"{{"access_token":"{access_token}","expires_in":3600,"encrypted_payload":"{encrypted_payload}"}}"#
        )
    }

    #[test]
    fn past_datetime_maps_to_now_or_earlier() {
        let past = Utc::now() - chrono::Duration::minutes(5);
        let instant = datetime_to_instant(past);
        assert!(instant <= std::time::Instant::now() + Duration::from_millis(100));
    }

    #[test]
    fn future_datetime_maps_to_future_instant() {
        let future = Utc::now() + chrono::Duration::minutes(5);
        let instant = datetime_to_instant(future);
        assert!(instant > std::time::Instant::now());
    }

    // execute_by is past, so arm 1 fires before phase() is awaited.

    #[tokio::test]
    async fn gate_lease_expired_aborts() {
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        use crate::auth::{identity::IdentityClient, session::SessionManager};

        let server = MockServer::start().await;
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = encrypted_payload_for(&org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(identity_ok_body(&payload))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let token = test_token();
        let identity = IdentityClient::new(server.uri()).unwrap();
        let session = SessionManager::new(identity, token, KeyStore::default())
            .await
            .unwrap();

        let cancel = bitwarden_threading::cancellation_token::CancellationToken::new();
        let last_ok: Arc<dyn Fn() -> std::time::Instant + Send + Sync> =
            Arc::new(std::time::Instant::now);

        let execute_by = std::time::Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(std::time::Instant::now);

        let mut gate = make_gate(
            Arc::clone(&session),
            execute_by,
            Duration::from_secs(60),
            last_ok,
            cancel,
        );

        let result = gate().await;
        assert!(matches!(result, Err(AbortReason::LeaseExpired)));
    }

    // cancel is pre-cancelled, so arm 2 fires before session.phase().

    #[tokio::test]
    async fn gate_cancelled_aborts() {
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        use crate::auth::{identity::IdentityClient, session::SessionManager};

        let server = MockServer::start().await;
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = encrypted_payload_for(&org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(identity_ok_body(&payload))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let token = test_token();
        let identity = IdentityClient::new(server.uri()).unwrap();
        let session = SessionManager::new(identity, token, KeyStore::default())
            .await
            .unwrap();

        let cancel = bitwarden_threading::cancellation_token::CancellationToken::new();
        cancel.cancel();

        let execute_by = std::time::Instant::now() + Duration::from_secs(300);
        let last_ok: Arc<dyn Fn() -> std::time::Instant + Send + Sync> =
            Arc::new(std::time::Instant::now);

        let mut gate = make_gate(
            Arc::clone(&session),
            execute_by,
            Duration::from_secs(60),
            last_ok,
            cancel,
        );

        let result = gate().await;
        assert!(matches!(result, Err(AbortReason::Cancelled)));
    }

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
            self.rotate_result
                .as_ref()
                .map(|_| ())
                .map_err(|e| IntegrationError {
                    class: e.class,
                    effect: e.effect,
                    code: e.code,
                    detail: SafeDetail::from_kind("mock"),
                })
        }

        async fn verify(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            self.verify_result
                .as_ref()
                .map(|_| ())
                .map_err(|e| IntegrationError {
                    class: e.class,
                    effect: e.effect,
                    code: e.code,
                    detail: SafeDetail::from_kind("mock"),
                })
        }

        async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            self.terminate_result
                .as_ref()
                .map(|_| ())
                .map_err(|e| IntegrationError {
                    class: e.class,
                    effect: e.effect,
                    code: e.code,
                    detail: SafeDetail::from_kind("mock"),
                })
        }
    }

    #[test]
    fn target_effect_to_sync_state_mapping() {
        assert_eq!(
            RotationSyncState::from(TargetEffect::NotApplied),
            RotationSyncState::TargetUnchanged
        );
        assert_eq!(
            RotationSyncState::from(TargetEffect::Unknown),
            RotationSyncState::Indeterminate
        );
        assert_eq!(
            RotationSyncState::from(TargetEffect::Applied),
            RotationSyncState::TargetUpdated
        );
    }

    #[test]
    fn rotate_context_debug_redacts_password() {
        let ctx = RotateContext {
            target_system_id: uuid::Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: zeroize::Zeroizing::new("super-secret".to_string()),
            creds: ResolvedCredentials::new(),
            rotation_started_at: Utc::now(),
        };
        let debug = format!("{ctx:?}");
        assert!(!debug.contains("super-secret"), "password must be redacted");
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn mock_integration_tracks_rotate_calls() {
        let mock = MockIntegration::always_ok();
        assert_eq!(*mock.rotate_calls.lock().unwrap(), 0);
    }

    #[test]
    fn failure_code_for_unsupported_kind_is_correct() {
        let code = RotationFailureCode::UnsupportedKind;
        let s = serde_json::to_string(&code).unwrap();
        assert_eq!(s, r#""unsupported_kind""#);
    }

    /// What a [`run_execute`] call observed.
    struct Run {
        result: ExecutionResult,
        rotate_calls: u32,
        requests: Vec<wiremock::Request>,
        store: KeyStore<KeySlotIds>,
    }

    impl Run {
        fn requests_to(&self, method: &str, suffix: &str) -> Vec<&wiremock::Request> {
            self.requests
                .iter()
                .filter(|r| r.method.as_str() == method && r.url.path().ends_with(suffix))
                .collect()
        }

        fn failure_body(&self) -> serde_json::Value {
            let reqs = self.requests_to("POST", "/failure");
            assert_eq!(reqs.len(), 1, "expected exactly one failure report");
            serde_json::from_slice(&reqs[0].body).expect("parse failure body")
        }
    }

    /// Runs one rotation against mock servers. `cipher_gets` serve successive `GET /cipher` calls
    /// (pre-flight, then pre-write); the last repeats.
    async fn run_execute(make: impl FnOnce() -> Vec<ResponseTemplate>) -> Run {
        run_execute_for(crate::test_support::KEYED_LOGIN_ID, make).await
    }

    /// [`run_execute`] for a claim naming `cipher_id`.
    async fn run_execute_for(
        cipher_id: uuid::Uuid,
        make: impl FnOnce() -> Vec<ResponseTemplate>,
    ) -> Run {
        use bitwarden_pam::WorkSnapshot;
        use bitwarden_pam_sealed::SealedTargetSystemKind;
        use tokio::sync::watch;
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        use crate::{
            api::{REQUEST_TIMEOUT, build_sdk_client},
            auth::{identity::IdentityClient, session::SessionManager},
            integrations::IntegrationRegistry,
            resolver::{CredentialResolver, ResolveError, ResolvedCredentials},
            test_support::{sample_config, sample_target, sealed_pair},
        };

        // The cipher vectors are encrypted under this org key, so the session must install it.
        let org_key = crate::test_support::fixture_org_key();
        let payload = encrypted_payload_for(&org_key);

        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(identity_ok_body(&payload))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&identity_server)
            .await;

        let attempt_id = uuid::Uuid::new_v4();
        let job_id = uuid::Uuid::new_v4();
        let target_system_id = uuid::Uuid::new_v4();

        // The client's own key store, which the session installs the org key into.
        let (tx, _rx) = watch::channel(std::time::Instant::now());
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

        let mut gets = make();
        let last = gets.pop().expect("at least one GET response");
        let cipher_path = format!("/access-connectors/rotation/attempts/{attempt_id}/cipher");
        for get in gets {
            Mock::given(method("GET"))
                .and(path(cipher_path.clone()))
                .respond_with(get)
                .up_to_n_times(1)
                .mount(&api_server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(cipher_path.clone()))
            .respond_with(last)
            .mount(&api_server)
            .await;
        Mock::given(method("PUT"))
            .and(path(cipher_path))
            .respond_with(ResponseTemplate::new(200))
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
                _id: uuid::Uuid,
                _kind: SealedTargetSystemKind,
            ) -> Result<ResolvedCredentials, ResolveError> {
                Ok(ResolvedCredentials::new())
            }
        }

        let integ = MockIntegration::always_ok();
        let rotate_calls = Arc::clone(&integ.rotate_calls);
        let mut registry = IntegrationRegistry::new();
        registry.register(SealedTargetSystemKind::CustomScript, Arc::new(integ));

        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let last_ok_time = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let last_ok_clone = Arc::clone(&last_ok_time);
        let exec_ctx = ExecutionContext {
            client,
            session: Arc::clone(&session),
            integrations: Arc::new(registry),
            resolver: Arc::new(AlwaysOkResolver),
            organization_id: test_org_id(),
            retry_cfg: crate::executor::retry::RetryCfg {
                max_retry_attempts: 1,
                retry_base_delay: std::time::Duration::from_millis(0),
            },
            offline_grace: std::time::Duration::from_secs(60),
            last_ok: Arc::new(move || *last_ok_clone.lock().unwrap()),
            cancel: bitwarden_threading::cancellation_token::CancellationToken::new(),
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

        let result = execute(job, &exec_ctx).await;
        let calls = *rotate_calls.lock().unwrap();
        Run {
            result,
            rotate_calls: calls,
            requests: api_server.received_requests().await.unwrap(),
            store,
        }
    }

    fn json_response(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(body)
            .insert_header("content-type", "application/json")
    }

    /// A `get_cipher` protocol error after a successful rotate reports `target_updated`.
    #[tokio::test]
    async fn get_cipher_protocol_error_after_rotate_reports_target_updated() {
        // The first GET is the pre-flight read and must succeed; the second breaks.
        let run = run_execute(|| {
            vec![
                json_response(crate::test_support::keyed_login_json()),
                ResponseTemplate::new(200)
                    .set_body_string("NOT JSON")
                    .insert_header("content-type", "application/json"),
            ]
        })
        .await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 1);
        assert_eq!(run.failure_body()["syncState"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn preflight_cipher_id_mismatch_rejects_before_any_integration_call() {
        let mut json = keyed_login_json();
        json["id"] = uuid::Uuid::new_v4().to_string().into();
        let run = run_execute(|| vec![json_response(json)]).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 0, "rotate must not run");
        let body = run.failure_body();
        assert_eq!(body["errorCode"], serde_json::json!("sealed_data_rejected"));
        assert_eq!(body["syncState"], serde_json::json!(0));
    }

    /// A cipher that cannot be rotated fails the pre-flight, before the target is touched. The
    /// claim names `cipher_id`, the id of the vector `json` is derived from.
    async fn assert_preflight_rejects(cipher_id: uuid::Uuid, json: serde_json::Value) {
        let run = run_execute_for(cipher_id, || vec![json_response(json)]).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 0, "rotate must not run");
        assert!(run.requests_to("PUT", "/cipher").is_empty());
        let body = run.failure_body();
        assert_eq!(body["errorCode"], serde_json::json!("sealed_data_rejected"));
        assert_eq!(body["syncState"], serde_json::json!(0));
    }

    #[tokio::test]
    async fn preflight_rejects_cipher_of_another_organization() {
        let mut json = keyed_login_json();
        json["organizationId"] = uuid::Uuid::new_v4().to_string().into();
        assert_preflight_rejects(KEYED_LOGIN_ID, json).await;
    }

    #[tokio::test]
    async fn preflight_rejects_non_login_cipher() {
        let mut json = keyed_login_json();
        json["type"] = 2.into();
        assert_preflight_rejects(KEYED_LOGIN_ID, json).await;
    }

    #[tokio::test]
    async fn rotation_of_cipher_with_item_key_and_attachments_succeeds() {
        let run = run_execute_for(KEYED_LOGIN_WITH_ATTACHMENT_ID, || {
            vec![json_response(vector_json(KEYED_LOGIN_WITH_ATTACHMENT))]
        })
        .await;

        assert_eq!(run.rotate_calls, 1);
        assert_eq!(run.requests_to("PUT", "/cipher").len(), 1);
    }

    #[tokio::test]
    async fn preflight_rejects_restricted_cipher() {
        assert_preflight_rejects(RESTRICTED_LOGIN_ID, vector_json(RESTRICTED_LOGIN)).await;
    }

    /// Lenient decryption would drop the field and the write wipe it; strict fails the pre-flight.
    #[tokio::test]
    async fn preflight_rejects_cipher_with_undecryptable_field() {
        use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let other = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let foreign = "x".encrypt_with_key(&other).unwrap().to_string();
        let mut json = keyed_login_json();
        json["notes"] = foreign.into();
        assert_preflight_rejects(KEYED_LOGIN_ID, json).await;
    }

    #[tokio::test]
    async fn rotation_writes_typed_cipher_with_history() {
        let json = keyed_login_json();
        let original_key = json["key"].as_str().unwrap().to_owned();
        assert_eq!(
            json["revisionDate"],
            crate::test_support::CIPHER_REVISION_DATE
        );
        let run = run_execute(|| vec![json_response(json)]).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 1);
        assert_eq!(run.requests_to("POST", "/success").len(), 1);

        let puts = run.requests_to("PUT", "/cipher");
        assert_eq!(puts.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&puts[0].body).expect("PUT body");
        let dec = |p| crate::test_support::decrypt_body_field(&run.store, &body, p);

        // The item key is sent back exactly as fetched, and the new fields decrypt under it.
        assert_eq!(body["key"], original_key.as_str());
        let mut original_body = body.clone();
        original_body["key"] = original_key.into();
        assert_eq!(
            crate::test_support::decrypt_body_field(&run.store, &original_body, "/login/password"),
            dec("/login/password")
        );

        // The password the integration set is what was written, and the old one is in history.
        assert_ne!(dec("/login/password"), "old-password");
        assert_eq!(dec("/passwordHistory/0/password"), "old-password");
        assert_eq!(dec("/passwordHistory/1/password"), "older-password");
        assert!(body["login"]["passwordRevisionDate"].is_string());
        assert_eq!(body["lastKnownRevisionDate"], "2024-06-01T12:00:00Z");
        assert!(body["data"].is_null());
        assert_eq!(body["organizationId"], test_org_id().to_string());
        assert_eq!(body["type"], 1);
        assert_eq!(dec("/login/username"), "svc-account");
        assert_eq!(dec("/login/uris/0/uri"), "https://db.example.com");
        assert_eq!(dec("/name"), "Prod database");
    }

    /// A keyless cipher would make the vault generate an item key, so it is rejected up front.
    async fn assert_keyless_rejected(attachments: bool) {
        let mut json = vector_json(KEYLESS_LOGIN);
        if attachments {
            json["attachments"] = crate::test_support::attachments_json();
        }
        let run = run_execute_for(KEYLESS_LOGIN_ID, || vec![json_response(json)]).await;

        assert!(matches!(run.result, ExecutionResult::Reported));
        assert_eq!(run.rotate_calls, 0, "rotate must not run");
        assert!(run.requests_to("PUT", "/cipher").is_empty());
        let body = run.failure_body();
        assert_eq!(body["errorCode"], serde_json::json!("sealed_data_rejected"));
        assert_eq!(body["syncState"], serde_json::json!(0));
    }

    #[tokio::test]
    async fn preflight_rejects_cipher_without_item_key() {
        assert_keyless_rejected(false).await;
    }

    #[tokio::test]
    async fn preflight_rejects_attachments_without_item_key() {
        assert_keyless_rejected(true).await;
    }
}
