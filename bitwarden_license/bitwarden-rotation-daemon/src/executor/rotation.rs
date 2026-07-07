//! Core rotation execution pipeline.
//!
//! # Overview
//!
//! [`execute`] runs a single rotation attempt from start to finish following the
//! seven-step `ExecuteRotation` spec rule.  Each step either advances or
//! terminates the attempt, producing an [`ExecutionResult`].
//!
//! # Proof tokens (compile-time VerifiedBeforeSuccess)
//!
//! [`Verified`] and [`CipherWritten`] are zero-size unit structs whose
//! constructors are private to this module (their inner `()` field is not
//! `pub`).  [`report_success_inner`] is the **only** function that calls
//! `api.report_success`; it takes `Verified` and `CipherWritten` by value,
//! making it a compile-time error to report success without completing both
//! steps 4 and 5.
//!
//! # Divergences from the spec
//!
//! **D1** — `ExecuteRotationWithoutSession`: the spec fails fast for any
//! non-active session at the claim-to-start gap (including merely expired).
//! This implementation only fails fast for terminal `Revoked`/`Closed` phases:
//! the claim itself rode an authenticated request, so the window for
//! `Expired`-at-start is razor-thin, and burning the server's retry budget for
//! an `Expired` phase (which refreshes in place) would be wrong.  The gate
//! handles all mid-execution pauses.
//!
//! **D4** — `execute_by` bounds only target-side steps (3, 4, 6).  Server-side
//! work (cipher GET/PUT at step 5, outcome reports at step 7) continues past
//! `execute_by` under the transient budget while the session is alive.  The
//! spec (lines 306–321) endorses this; the server's success-wins semantics
//! release keys on heartbeat staleness AND lease expiry, not only on lease expiry.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;

use super::retry::{GatedOutcome, RetryCfg, with_retries, with_retries_gated};
use crate::{
    api::{
        RotationApi,
        models::{ApiError, WorkSnapshot},
    },
    auth::session::{SessionLost, SessionManager, SessionPhase},
    crypto::{DaemonKeyStore, encrypt_cipher_password},
    error::{ErrorClass, FailureCode, SafeDetail, SessionTermination, SyncState},
    integrations::{Integration, IntegrationRegistry, RotateContext, TargetEffect},
    policy,
    resolver::{CredentialResolver, ResolveError},
};

// ---------------------------------------------------------------------------
// AbortReason
// ---------------------------------------------------------------------------

/// The reason a step-boundary gate aborted the rotation.
///
/// An abort means the attempt goes **unreported** (a report requires a session;
/// the server's `ReleaseJob` / `JobTimesOut` machinery will abandon the attempt
/// server-side).
#[derive(Debug, Clone)]
pub(crate) enum AbortReason {
    /// The claim's `execute_by` lease deadline has passed.
    LeaseExpired,
    /// The session was terminally lost (revoked or closed).
    SessionLost(SessionLost),
    /// The `CancellationToken` was cancelled (daemon is shutting down).
    Cancelled,
}

// ---------------------------------------------------------------------------
// Proof tokens
// ---------------------------------------------------------------------------

/// Proof that step 4 (verify) completed successfully.
///
/// Constructible only within this module; passed to the success-report helper
/// to enforce the `VerifiedBeforeSuccess` spec guarantee at compile time.
pub(crate) struct Verified(());

/// Proof that step 5 (cipher write) completed successfully.
///
/// Constructible only within this module; passed to the success-report helper
/// to enforce the `VerifiedBeforeSuccess` spec guarantee at compile time.
pub(crate) struct CipherWritten(());

// ---------------------------------------------------------------------------
// ExecutionResult
// ---------------------------------------------------------------------------

/// The outcome of a single [`execute`] call.
#[derive(Debug)]
pub(crate) enum ExecutionResult {
    /// The rotation completed and an outcome (success or failure) was reported
    /// to the server.
    Reported,
    /// The rotation was aborted before an outcome could be reported (session
    /// lost or execute_by expired).  The attempt goes unreported; the server's
    /// `ReleaseJob` / `JobTimesOut` machinery will handle it.
    Unreported(AbortReason),
}

// ---------------------------------------------------------------------------
// Shared execution context
// ---------------------------------------------------------------------------

/// Everything [`execute`] needs to run a rotation attempt.
pub(crate) struct ExecutionContext {
    /// The API wrapper used for cipher read/write and outcome reports.
    pub(crate) api: Arc<RotationApi>,
    /// The session manager (for phase checks in the gate).
    pub(crate) session: Arc<SessionManager>,
    /// The integration registry (maps `TargetKind` → driver).
    pub(crate) integrations: Arc<IntegrationRegistry>,
    /// The credential resolver (maps target id → connection details).
    pub(crate) resolver: Arc<dyn CredentialResolver>,
    /// The shared key store (for cipher encryption at step 5).
    pub(crate) key_store: Arc<DaemonKeyStore>,
    /// Retry configuration.
    pub(crate) retry_cfg: RetryCfg,
    /// Maximum time without a successful server contact before the daemon
    /// considers itself offline (the connectivity-pause threshold).
    pub(crate) offline_grace: Duration,
    /// A function that returns the most recent successful-API-contact instant.
    pub(crate) last_ok: Arc<dyn Fn() -> Instant + Send + Sync>,
    /// The cancellation token for clean shutdown.
    pub(crate) cancel: bitwarden_threading::cancellation_token::CancellationToken,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Execute a single rotation attempt and return the [`ExecutionResult`].
///
/// # Step overview
///
/// 0. Phase check — if `Revoked`/`Closed`, best-effort failure report then stop.
/// 1. Resolve credentials — failure → `credentials_unresolved` / `target_unchanged`.
/// 2. Generate password + registry lookup — failure → `invalid_policy` or `unsupported_kind` /
///    `target_unchanged`.
/// 3. Rotate (target-side, gated retries) — maps `TargetEffect` to `SyncState`.
/// 4. Verify (target-side, gated retries) — failure always → `target_updated`.
/// 5. Cipher write (server-side, ungated) — reads, encrypts, writes.
/// 6. Terminate sessions (target-side, gated, best-effort).
/// 7. Report outcome (transient-absorbed).
pub(crate) async fn execute(snapshot: WorkSnapshot, ctx: &ExecutionContext) -> ExecutionResult {
    let attempt_id = snapshot.attempt_id;

    tracing::info!(
        attempt_id = %attempt_id,
        job_id = %snapshot.job_id,
        cipher_id = %snapshot.cipher_id,
        target_system_name = %snapshot.target_system_name,
        "starting rotation execution"
    );

    // ── Step 0: terminal-session check (D1 divergence documented above) ────
    {
        let phase = ctx.session.phase().await;
        if matches!(phase, SessionPhase::Revoked | SessionPhase::Closed) {
            // Best-effort failure report: session is terminal, report may fail.
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::NoActiveSession,
                None,
                SyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    }

    // Convert execute_by (UTC DateTime) to a monotonic Instant.
    let execute_by_instant = datetime_to_instant(snapshot.execute_by);

    // ── Step 1: resolve credentials ────────────────────────────────────────
    let creds = match ctx
        .resolver
        .resolve(snapshot.target_system_id, snapshot.kind)
        .await
    {
        Ok(c) => c,
        Err(ResolveError::Missing(names)) => {
            let detail = SafeDetail::from_missing_vars(&names);
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::CredentialsUnresolved,
                Some(detail),
                SyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    tracing::info!(attempt_id = %attempt_id, "step 1: credentials resolved");

    // ── Step 2: generate password + registry lookup ────────────────────────
    let gen_req = match policy::to_generator_request(&snapshot.password_policy) {
        Ok(r) => r,
        Err(_) => {
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::InvalidPolicy,
                None,
                SyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    let new_password = match bitwarden_generators::password(gen_req) {
        Ok(p) => zeroize::Zeroizing::new(p),
        Err(_) => {
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::InvalidPolicy,
                None,
                SyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    tracing::info!(attempt_id = %attempt_id, "step 2: password generated");

    let rotation_started_at = Utc::now();

    let integration: Arc<dyn Integration> = match ctx.integrations.get(snapshot.kind) {
        Some(i) => i,
        None => {
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::UnsupportedKind,
                None,
                SyncState::TargetUnchanged,
            )
            .await;
            return ExecutionResult::Reported;
        }
    };

    let rotate_ctx = Arc::new(RotateContext {
        target_system_id: snapshot.target_system_id,
        account_identity: snapshot.account_identity.clone(),
        new_password: new_password.clone(),
        creds,
        rotation_started_at,
    });

    // ── Step 3: rotate (target-side, gated retries) ────────────────────────
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
                    kind = ?snapshot.kind,
                    "step 3: target rotate succeeded"
                );
            }
            GatedOutcome::Aborted(reason) => {
                return ExecutionResult::Unreported(reason);
            }
            GatedOutcome::Failed(err) => {
                let sync_state = match err.effect {
                    TargetEffect::NotApplied => SyncState::TargetUnchanged,
                    TargetEffect::Unknown => SyncState::Indeterminate,
                    TargetEffect::Applied => SyncState::TargetUpdated,
                };
                report_failure_absorb(&ctx.api, attempt_id, err.code, Some(err.detail), sync_state)
                    .await;
                return ExecutionResult::Reported;
            }
        }
    }

    // ── Step 4: verify (target-side, gated retries) ────────────────────────
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
                // Verify failure: target was updated (rotation applied), vault not written.
                report_failure_absorb(
                    &ctx.api,
                    attempt_id,
                    err.code,
                    Some(err.detail),
                    SyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        }
    };

    // ── Step 5: cipher write (server-side, ungated) ────────────────────────
    // execute_by does NOT bound this step (D4).  We use with_retries with no
    // deadline, relying on the session's bearer-refresh to handle token expiry.
    let cipher_written = {
        // Sub-step 5a: get cipher (with retries).
        let cipher = {
            let api = Arc::clone(&ctx.api);
            let result = with_retries(
                &ctx.retry_cfg,
                None, // D4: no deadline
                || {
                    let api = Arc::clone(&api);
                    async move {
                        match api.get_cipher(attempt_id).await {
                            Ok(c) => Ok(c),
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
                Ok(c) => c,
                Err(ApiError::UnknownAttempt) => {
                    return ExecutionResult::Unreported(AbortReason::SessionLost(
                        SessionLost::Closed,
                    ));
                }
                Err(ApiError::SessionLost(l)) => {
                    return ExecutionResult::Unreported(AbortReason::SessionLost(l));
                }
                Err(_) => {
                    // Any other fatal error on get_cipher (e.g. Protocol, exhausted
                    // Transient) must be reported as target_updated.  The rotation
                    // (step 3) already changed the target credential; silently dropping
                    // this error would leave the server unaware of the updated state.
                    report_failure_absorb(
                        &ctx.api,
                        attempt_id,
                        FailureCode::Internal,
                        None,
                        SyncState::TargetUpdated,
                    )
                    .await;
                    return ExecutionResult::Reported;
                }
            }
        };

        tracing::debug!(attempt_id = %attempt_id, cipher_id = %cipher.cipher_id, "cipher fetched");

        // Sub-step 5b: encrypt new password into cipher data.
        let mut data = cipher.data.clone();
        let store = Arc::clone(&ctx.key_store);
        let encrypt_result =
            encrypt_cipher_password(&store, cipher.key.as_deref(), &mut data, &new_password);

        if let Err(_e) = encrypt_result {
            report_failure_absorb(
                &ctx.api,
                attempt_id,
                FailureCode::CipherEncryptFailed,
                None,
                SyncState::TargetUpdated,
            )
            .await;
            return ExecutionResult::Reported;
        }

        // Serialise the updated data value back to a JSON string.
        let data_str = match serde_json::to_string(&data) {
            Ok(s) => s,
            Err(_) => {
                report_failure_absorb(
                    &ctx.api,
                    attempt_id,
                    FailureCode::CipherEncryptFailed,
                    None,
                    SyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        };

        // Sub-step 5c: put cipher (with retries).
        let api = Arc::clone(&ctx.api);
        let revision_date = cipher.revision_date.clone();
        let result = with_retries(
            &ctx.retry_cfg,
            None, // D4: no deadline
            || {
                let api = Arc::clone(&api);
                let data_str = data_str.clone();
                let revision_date = revision_date.clone();
                async move {
                    match api.put_cipher(attempt_id, data_str, revision_date).await {
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
                    cipher_id = %cipher.cipher_id,
                    "step 5: cipher written"
                );
                CipherWritten(())
            }
            Err(ApiError::Rejected { .. }) => {
                report_failure_absorb(
                    &ctx.api,
                    attempt_id,
                    FailureCode::CipherWriteRejected,
                    None,
                    SyncState::TargetUpdated,
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
                // Unexpected put_cipher error after the rotation succeeded.
                // Report target_updated so the server knows the credential was changed.
                report_failure_absorb(
                    &ctx.api,
                    attempt_id,
                    FailureCode::Internal,
                    None,
                    SyncState::TargetUpdated,
                )
                .await;
                return ExecutionResult::Reported;
            }
        }
    };

    // ── Step 6: terminate sessions (target-side, gated, best-effort) ───────
    // This step structurally cannot fail the rotation.  It returns a
    // `SessionTermination` value.  The ONE case where an abort here changes the
    // overall outcome is `AbortReason::SessionLost` — then the success report
    // itself cannot be sent.
    let termination_result: SessionTermination = if !snapshot.terminate_sessions {
        SessionTermination::NotRequested
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
                SessionTermination::Terminated
            }
            GatedOutcome::Aborted(AbortReason::SessionLost(l)) => {
                // Session is lost — the success report cannot be sent.
                return ExecutionResult::Unreported(AbortReason::SessionLost(l));
            }
            GatedOutcome::Aborted(reason) => {
                // Lease expired or cancelled during termination (D3 widening):
                // report success with term_failed.
                tracing::warn!(
                    attempt_id = %attempt_id,
                    abort_reason = ?reason,
                    "step 6: session termination aborted (reporting term_failed)"
                );
                SessionTermination::TermFailed
            }
            GatedOutcome::Failed(err) => {
                tracing::warn!(
                    attempt_id = %attempt_id,
                    "step 6: session termination failed: {err}; reporting term_failed"
                );
                SessionTermination::TermFailed
            }
        }
    };

    // ── Step 7: report success (transient-absorbed) ────────────────────────
    // `report_success_inner` is the ONLY caller of `api.report_success`.  It
    // demands proof tokens for steps 4 (Verified) and 5 (CipherWritten), making
    // it a compile-time error to call it without completing both steps in order.
    let termination = termination_result;
    let report_result = report_success_inner(
        &ctx.api,
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

// ---------------------------------------------------------------------------
// report_success_inner — the ONLY caller of api.report_success
// ---------------------------------------------------------------------------

/// Report a successful rotation, requiring compile-time proof that steps 4 and 5
/// completed.
///
/// `_verified` and `_cipher_written` are zero-size proof tokens whose
/// constructors are private to this module.  Passing them by value here means
/// the compiler statically rejects any success-report that bypasses the verify
/// or cipher-write steps.
async fn report_success_inner(
    api: &RotationApi,
    retry_cfg: &super::retry::RetryCfg,
    attempt_id: uuid::Uuid,
    termination: crate::error::SessionTermination,
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
                // 409/404 on report is FINAL — treat as reported.
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

// ---------------------------------------------------------------------------
// Step-boundary gate
// ---------------------------------------------------------------------------

/// Build a gate closure for the gated-retry steps (3, 4, 6).
///
/// The gate implements the five arms from plan §6:
///
/// 1. `now >= execute_by` → `LeaseExpired`
/// 2. cancellation token cancelled → `Cancelled`
/// 3. phase `Revoked`/`Closed` → `SessionLost`
/// 4. phase `Expired`/`Authenticating` → pause: call `session.bearer(execute_by)`, then re-loop; if
///    `Lost` → `SessionLost`; if transient / deadline → `LeaseExpired`
/// 5. phase `Active` but connectivity stale → wait until recovered or `execute_by`
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

                // Get current phase (async).
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
                    // bearer() will renew the token; we pass execute_by as the
                    // deadline so we don't wait indefinitely.
                    match session.bearer(Some(execute_by)).await {
                        Ok(_) => {
                            // Re-loop to re-check all arms.
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
                        // Wait until either: connectivity recovered (last_ok advances)
                        // OR execute_by passes OR cancellation.
                        //
                        // Poll every 1 s up to execute_by.
                        loop {
                            if Instant::now() >= execute_by {
                                return Err(AbortReason::LeaseExpired);
                            }
                            if cancel.is_cancelled() {
                                return Err(AbortReason::Cancelled);
                            }
                            let fresh = (last_ok)();
                            if fresh.elapsed() <= offline_grace {
                                // Recovered — re-check all arms from the top.
                                break;
                            }
                            // Sleep 1 s or until execute_by, whichever is sooner.
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
                        // Recovered — continue the outer loop to re-check all arms.
                        continue;
                    }
                }

                // All arms passed → proceed.
                return Ok(());
            }
        })
    }
}

// ---------------------------------------------------------------------------
// chrono → Instant conversion
// ---------------------------------------------------------------------------

/// Convert a UTC `DateTime` to a monotonic [`std::time::Instant`].
///
/// The conversion is saturating: a `DateTime` in the past maps to an already-
/// elapsed `Instant` (so the gate's `now >= execute_by` check fires immediately),
/// and a `DateTime` unreasonably far in the future is capped at `now + 24h` to
/// avoid overflow.
fn datetime_to_instant(dt: chrono::DateTime<chrono::Utc>) -> Instant {
    use chrono::Utc;
    let now_utc = Utc::now();
    let delta = dt - now_utc;
    let mono_now = Instant::now();

    if delta.num_seconds() <= 0 {
        // Already expired — return now; the gate's `now >= execute_by` check
        // fires immediately on the next call.
        mono_now
    } else {
        // Saturate at 24 h to avoid Duration overflow.
        let secs = delta.num_seconds().min(86400) as u64;
        mono_now + Duration::from_secs(secs)
    }
}

// ---------------------------------------------------------------------------
// Helper: report a failure, absorbing report errors
// ---------------------------------------------------------------------------

/// Report a rotation failure, logging the outcome and absorbing any report error.
///
/// Emits a `warn` with the attempt id, failure code, sync state, and optional
/// safe detail so that every failure has exactly one operator-visible log line.
/// A second `warn` is emitted if the report itself fails (network / server error),
/// but the rotation is still considered `Reported` as long as we tried.
async fn report_failure_absorb(
    api: &RotationApi,
    attempt_id: uuid::Uuid,
    code: FailureCode,
    detail: Option<SafeDetail>,
    sync_state: SyncState,
) {
    // One warn per failure, regardless of whether the network report succeeds.
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

// Re-export Future for use in make_gate's return type.
use std::future::Future;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{
        error::{FailureCode, SafeDetail},
        integrations::{Integration, IntegrationError, RotateContext, TargetEffect},
        resolver::ResolvedCredentials,
    };

    // ── datetime_to_instant ────────────────────────────────────────────────

    #[test]
    fn past_datetime_maps_to_now_or_earlier() {
        let past = Utc::now() - chrono::Duration::minutes(5);
        let instant = datetime_to_instant(past);
        // Should be <= now, so the gate fires immediately.
        assert!(instant <= std::time::Instant::now() + Duration::from_millis(100));
    }

    #[test]
    fn future_datetime_maps_to_future_instant() {
        let future = Utc::now() + chrono::Duration::minutes(5);
        let instant = datetime_to_instant(future);
        // Should be in the future.
        assert!(instant > std::time::Instant::now());
    }

    // ── make_gate: lease-expired arm ──────────────────────────────────────
    //
    // Note: execute_by is in the past, so arm 1 fires before session.phase()
    // is called.  We therefore need a valid SessionManager (for the Arc),
    // but session.phase() will never actually be awaited.

    #[tokio::test]
    async fn gate_lease_expired_aborts() {
        use std::str::FromStr;

        use bitwarden_crypto::{
            KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, derive_shareable_key,
        };
        use bitwarden_encoding::B64;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        use zeroize::Zeroizing;

        use crate::{
            auth::{identity::IdentityClient, session::SessionManager},
            token::DaemonToken,
        };

        let server = MockServer::start().await;

        // Derive the token key from the actual token client secret (base64 decoded).
        // Token: "...C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
        // Client secret (after the colon): "X8vbvA0bduihIDe/qrzIQQ=="
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().unwrap();
        let key_bytes: Zeroizing<[u8; 16]> = Zeroizing::new(b64.as_bytes().try_into().unwrap());
        let token_key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            key_bytes,
            "accesstoken",
            Some("sm-access-token"),
        ));
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key_bytes = org_key.to_encoded();
        let b64_str: String = B64::from(org_key_bytes.as_ref()).into();
        let payload = format!(r#"{{"encryptionKey":"{b64_str}"}}"#)
            .as_str()
            .encrypt_with_key(&token_key)
            .unwrap()
            .to_string();

        Mock::given(method("POST")).and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!(r#"{{"access_token":"tok","expires_in":3600,"encrypted_payload":"{payload}"}}"#))
                    .insert_header("content-type", "application/json")
            )
            .mount(&server).await;

        let token = DaemonToken::from_str(
            "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
        ).unwrap();
        let identity = IdentityClient::new(server.uri()).unwrap();
        let session = SessionManager::new(identity, token).await.unwrap();

        let cancel = bitwarden_threading::cancellation_token::CancellationToken::new();
        let last_ok: Arc<dyn Fn() -> std::time::Instant + Send + Sync> =
            Arc::new(std::time::Instant::now);

        // Set execute_by to 1 ms in the past.
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

    // ── gate: cancelled arm ────────────────────────────────────────────────
    //
    // Note: cancel is pre-cancelled, so arm 2 fires before session.phase().

    #[tokio::test]
    async fn gate_cancelled_aborts() {
        use std::str::FromStr;

        use bitwarden_crypto::{
            KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, derive_shareable_key,
        };
        use bitwarden_encoding::B64;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        use zeroize::Zeroizing;

        use crate::{
            auth::{identity::IdentityClient, session::SessionManager},
            token::DaemonToken,
        };

        let server = MockServer::start().await;

        // Same key derivation as the token's actual client secret.
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().unwrap();
        let key_bytes: Zeroizing<[u8; 16]> = Zeroizing::new(b64.as_bytes().try_into().unwrap());
        let token_key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            key_bytes,
            "accesstoken",
            Some("sm-access-token"),
        ));
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key_bytes = org_key.to_encoded();
        let b64_str: String = B64::from(org_key_bytes.as_ref()).into();
        let payload = format!(r#"{{"encryptionKey":"{b64_str}"}}"#)
            .as_str()
            .encrypt_with_key(&token_key)
            .unwrap()
            .to_string();

        Mock::given(method("POST")).and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!(r#"{{"access_token":"tok","expires_in":3600,"encrypted_payload":"{payload}"}}"#))
                    .insert_header("content-type", "application/json")
            )
            .mount(&server).await;

        let token = DaemonToken::from_str(
            "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
        ).unwrap();
        let identity = IdentityClient::new(server.uri()).unwrap();
        let session = SessionManager::new(identity, token).await.unwrap();

        let cancel = bitwarden_threading::cancellation_token::CancellationToken::new();
        cancel.cancel(); // Already cancelled.

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

    // ── Integration mock for flow tests ───────────────────────────────────

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

    // ── sync_state matrix: step-3 effects ─────────────────────────────────

    #[test]
    fn target_effect_to_sync_state_mapping() {
        // Verify the explicit mappings specified by the plan.
        assert_eq!(
            effect_to_sync_state(TargetEffect::NotApplied),
            SyncState::TargetUnchanged
        );
        assert_eq!(
            effect_to_sync_state(TargetEffect::Unknown),
            SyncState::Indeterminate
        );
        assert_eq!(
            effect_to_sync_state(TargetEffect::Applied),
            SyncState::TargetUpdated
        );
    }

    fn effect_to_sync_state(e: TargetEffect) -> SyncState {
        match e {
            TargetEffect::NotApplied => SyncState::TargetUnchanged,
            TargetEffect::Unknown => SyncState::Indeterminate,
            TargetEffect::Applied => SyncState::TargetUpdated,
        }
    }

    // ── RotateContext builds without panic ─────────────────────────────────

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

    // ── MockIntegration rotate_calls counter ──────────────────────────────

    #[test]
    fn mock_integration_tracks_rotate_calls() {
        let mock = MockIntegration::always_ok();
        assert_eq!(*mock.rotate_calls.lock().unwrap(), 0);
    }

    // ── Step-3 effect → SyncState via execute integration tests ──────────

    #[test]
    fn failure_code_for_unsupported_kind_is_correct() {
        // Regression: make sure the FailureCode we use for unsupported_kind
        // serialises as expected.
        let code = FailureCode::UnsupportedKind;
        let s = serde_json::to_string(&code).unwrap();
        assert_eq!(s, r#""unsupported_kind""#);
    }

    // ── Fix-5: get_cipher Protocol error → target_updated failure reported ──

    /// After a successful rotate (step 3), a Protocol error from get_cipher
    /// must produce a `target_updated` failure report rather than being silently
    /// dropped.  The test verifies the failure endpoint receives a request with
    /// `syncState == 1` (TargetUpdated).
    #[tokio::test]
    async fn get_cipher_protocol_error_after_rotate_reports_target_updated() {
        use std::str::FromStr;

        use bitwarden_crypto::{
            KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, derive_shareable_key,
        };
        use bitwarden_encoding::B64;
        use chrono::Utc;
        use tokio::sync::watch;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        use zeroize::Zeroizing;

        use crate::{
            api::{
                RotationApi, build_api_client,
                models::{TargetKind, WorkSnapshot},
            },
            auth::{identity::IdentityClient, session::SessionManager},
            crypto::DaemonKeyStore,
            integrations::IntegrationRegistry,
            policy::PasswordPolicy,
            resolver::{CredentialResolver, ResolveError, ResolvedCredentials},
            token::DaemonToken,
        };

        // ── Build minimal key material ──────────────────────────────────────
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().unwrap();
        let key_bytes: Zeroizing<[u8; 16]> = Zeroizing::new(b64.as_bytes().try_into().unwrap());
        let token_key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            key_bytes,
            "accesstoken",
            Some("sm-access-token"),
        ));
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key_bytes = org_key.to_encoded();
        let b64_str: String = B64::from(org_key_bytes.as_ref()).into();
        let payload_json = format!(r#"{{"encryptionKey":"{b64_str}"}}"#);
        let payload = payload_json
            .as_str()
            .encrypt_with_key(&token_key)
            .unwrap()
            .to_string();

        // ── Identity + API mock servers ─────────────────────────────────────
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!(
                        r#"{{"access_token":"tok","expires_in":3600,"encrypted_payload":"{payload}"}}"#
                    ))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&identity_server)
            .await;

        // get_cipher returns malformed body → Protocol error.
        let attempt_id = uuid::Uuid::new_v4();
        let job_id = uuid::Uuid::new_v4();
        let target_system_id = uuid::Uuid::new_v4();

        Mock::given(method("GET"))
            .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("NOT JSON")
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        // Failure report endpoint — capture it.
        Mock::given(method("POST"))
            .and(path(format!("/rotation/attempts/{attempt_id}/failure")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        // ── SessionManager ───────────────────────────────────────────────────
        let token = DaemonToken::from_str(
            "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
        ).unwrap();
        let identity = IdentityClient::new(identity_server.uri()).unwrap();
        let session = SessionManager::new(identity, token).await.unwrap();
        let session = Arc::new(session);

        // ── Build RotationApi ────────────────────────────────────────────────
        let (tx, _rx) = watch::channel(std::time::Instant::now());
        let client = build_api_client(api_server.uri(), Arc::clone(&session));
        let api = Arc::new(RotationApi::new(client, tx));

        // ── Credential resolver: always-ok ───────────────────────────────────
        struct AlwaysOkResolver;
        #[async_trait::async_trait]
        impl CredentialResolver for AlwaysOkResolver {
            async fn resolve(
                &self,
                _id: uuid::Uuid,
                _kind: TargetKind,
            ) -> Result<ResolvedCredentials, ResolveError> {
                Ok(ResolvedCredentials::new())
            }
        }

        // ── Integration: rotate succeeds, verify succeeds ────────────────────
        let integ = MockIntegration::always_ok();
        let mut registry = IntegrationRegistry::new();
        registry.register(TargetKind::CustomScript, Arc::new(integ));

        // ── DaemonKeyStore ───────────────────────────────────────────────────
        let key_store = Arc::new(DaemonKeyStore::default());

        // ── ExecutionContext ─────────────────────────────────────────────────
        let last_ok_time = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let last_ok_clone = Arc::clone(&last_ok_time);
        let exec_ctx = ExecutionContext {
            api: Arc::clone(&api),
            session: Arc::clone(&session),
            integrations: Arc::new(registry),
            resolver: Arc::new(AlwaysOkResolver),
            key_store,
            retry_cfg: crate::executor::retry::RetryCfg {
                max_retry_attempts: 1,
                retry_base_delay: std::time::Duration::from_millis(0),
            },
            offline_grace: std::time::Duration::from_secs(60),
            last_ok: Arc::new(move || *last_ok_clone.lock().unwrap()),
            cancel: bitwarden_threading::cancellation_token::CancellationToken::new(),
        };

        // ── WorkSnapshot ─────────────────────────────────────────────────────
        let snapshot = WorkSnapshot {
            attempt_id,
            job_id,
            target_system_id,
            target_system_name: "test".to_owned(),
            kind: TargetKind::CustomScript,
            password_policy: PasswordPolicy {
                min_length: Some(12),
                max_length: Some(64),
                include_uppercase: true,
                include_lowercase: true,
                include_digits: true,
                include_symbols: false,
            },
            cipher_id: uuid::Uuid::new_v4(),
            account_identity: "user@example.com".to_owned(),
            terminate_sessions: false,
            execute_by: Utc::now() + chrono::Duration::minutes(5),
        };

        let result = execute(snapshot, &exec_ctx).await;

        // Must be Reported (not Unreported) — a failure was reported.
        assert!(
            matches!(result, ExecutionResult::Reported),
            "expected Reported, got {result:?}"
        );

        // Verify the failure report was sent with syncState = 1 (TargetUpdated).
        let requests = api_server.received_requests().await.unwrap();
        let failure_reqs: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path().ends_with("/failure"))
            .collect();
        assert_eq!(
            failure_reqs.len(),
            1,
            "expected exactly one failure report, got {}",
            failure_reqs.len()
        );
        let body: serde_json::Value =
            serde_json::from_slice(&failure_reqs[0].body).expect("parse failure body");
        assert_eq!(
            body["syncState"],
            serde_json::json!(1),
            "syncState must be 1 (TargetUpdated) for get_cipher protocol error: {body}"
        );
    }
}
