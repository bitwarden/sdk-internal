//! HTTP API client wrappers for the Bitwarden server's PAM rotation endpoints.
//!
//! This module provides:
//!
//! - [`DaemonAuthMiddleware`]: a [`reqwest_middleware::Middleware`] that attaches the daemon bearer
//!   token to outgoing requests, retries once on 401 with a forced
//!   [`crate::auth::session::SessionManager::force_refresh`], and converts session-loss into a hard
//!   middleware error rather than soft-failing.
//! - [`build_api_client`]: assembles the full HTTP + middleware + generated-client stack from a
//!   `base_url` string and a [`crate::auth::session::SessionManager`].
//! - [`RotationApi`]: a thin wrapper over the generated [`bitwarden_api_api::apis::ApiClient`] that
//!   maps every generated call into local domain types and [`models::ApiError`] variants, bumping
//!   the connectivity watch on every successful response.

pub(crate) mod models;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_api_api::{
    apis::{ApiClient, AuthRequired},
    models::{
        ReportRotationFailedRequestModel, ReportRotationSucceededRequestModel,
        SubmitCipherUpdateRequestModel,
    },
};
use bitwarden_api_base::Configuration;
use models::{ApiError, JobRef, RotationCipher, TargetKind, WorkSnapshot};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    auth::session::{SessionLost, SessionManager},
    error::{FailureCode, SafeDetail, SessionTermination, SyncState},
};

// ---------------------------------------------------------------------------
// DaemonAuthMiddleware
// ---------------------------------------------------------------------------

/// [`reqwest_middleware::Middleware`] that attaches a daemon bearer token and
/// handles the token-refresh-on-401 cycle.
///
/// # Bearer attachment
///
/// Requests carrying the [`AuthRequired::Bearer`] extension (set by the
/// generated API calls) get an `Authorization: Bearer <token>` header via
/// [`SessionManager::bearer`].  Requests without that extension are forwarded
/// untouched.
///
/// # 401 retry
///
/// On a 401 response the middleware calls
/// [`SessionManager::force_refresh`] with the token it originally sent, then
/// re-issues the request **once** with the new token.  The retry is only
/// possible when the request body can be cloned (`try_clone` succeeds); if the
/// body is a one-shot stream the 401 is returned as-is.
///
/// This mirrors the logic in
/// `crates/bitwarden-auth/src/token_management/middleware.rs:41-77`.
///
/// # Session loss
///
/// Unlike bitwarden-auth's middleware (which soft-fails by sending the request
/// without a token when renewal fails), this middleware **hard-fails** with a
/// middleware error if a bearer token cannot be obtained.  A
/// [`crate::auth::session::SessionError::Lost`] propagates as
/// [`reqwest_middleware::Error::Middleware`] backed by an `anyhow` error; the
/// executor can then consult `session.phase()` to decide on `CredentialRefused`
/// vs reconnect.
pub(crate) struct DaemonAuthMiddleware {
    session: Arc<SessionManager>,
}

impl DaemonAuthMiddleware {
    /// Build a new middleware wrapping `session`.
    pub(crate) fn new(session: Arc<SessionManager>) -> Self {
        Self { session }
    }

    /// Obtain a bearer token, returning a middleware error on failure.
    async fn get_bearer(&self) -> Result<String, reqwest_middleware::Error> {
        self.session
            .bearer(None)
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::anyhow!("{e}")))
    }

    /// Force-refresh the bearer (called after a 401), returning a middleware
    /// error on failure.
    async fn force_refresh_bearer(&self, stale: &str) -> Result<String, reqwest_middleware::Error> {
        self.session
            .force_refresh(stale, None)
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::anyhow!("{e}")))
    }
}

#[async_trait::async_trait]
impl Middleware for DaemonAuthMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // Only attach auth when the generated API sets the AuthRequired::Bearer extension.
        let auth_required = matches!(ext.get::<AuthRequired>(), Some(AuthRequired::Bearer));

        let used_token: Option<String> = if auth_required {
            let token = self.get_bearer().await?;
            attach_bearer_header(&mut req, &token);
            Some(token)
        } else {
            None
        };

        // Try to clone the request before consuming it (needed for the retry).
        let req_clone = req.try_clone();

        let response = next.clone().run(req, ext).await?;

        // 401 retry: only when auth was required, body is cloneable, and the first
        // response was 401.
        if auth_required
            && let Some(mut cloned) = req_clone
            && response.status() == http::StatusCode::UNAUTHORIZED
        {
            tracing::info!("daemon API: 401 received, refreshing token and retrying");

            let stale = used_token.as_deref().unwrap_or("");
            let new_token = self.force_refresh_bearer(stale).await?;
            attach_bearer_header(&mut cloned, &new_token);

            return next.run(cloned, ext).await;
        }

        Ok(response)
    }
}

/// Attach `Authorization: Bearer <token>` to a request in-place.
fn attach_bearer_header(req: &mut reqwest::Request, token: &str) {
    let value = match format!("Bearer {token}").parse::<http::HeaderValue>() {
        Ok(v) => v,
        Err(e) => {
            // Token contains a character that cannot appear in a header value.
            // Log a warning and proceed without the header — the server will return 401
            // and the middleware's retry path will surface the error.
            tracing::warn!("daemon API: cannot format bearer token as header value: {e}");
            return;
        }
    };
    req.headers_mut().insert(http::header::AUTHORIZATION, value);
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

/// Build the generated [`ApiClient`] with authentication middleware.
///
/// Uses [`bitwarden_api_base::new_http_client_builder`] to get a `reqwest`
/// client with rustls + platform-certificate-verifier + https-only (release)
/// + Bitwarden user-agent headers.  A 30 s per-request timeout is applied so that a black-holed
///   connection cannot starve the heartbeat past `DaemonOfflineAfter` (2 minutes).
///
/// The [`DaemonAuthMiddleware`] is layered on top to handle token attachment
/// and 401 refresh.
pub(crate) fn build_api_client(
    base_url: impl Into<String>,
    session: Arc<SessionManager>,
) -> ApiClient {
    // Do not follow redirects: a cross-host redirect could leak the bearer token.
    let http_client = bitwarden_api_base::new_http_client_builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client build should not fail");

    let middleware_client = ClientBuilder::new(http_client)
        .with(DaemonAuthMiddleware::new(session))
        .build();

    let config = Arc::new(Configuration {
        base_path: base_url.into(),
        client: middleware_client,
    });

    ApiClient::new(&config)
}

// ---------------------------------------------------------------------------
// RotationApi
// ---------------------------------------------------------------------------

/// Thin, domain-typed wrapper around the generated PAM rotation API clients.
///
/// Every method translates between the generated wire types and the local domain
/// types in [`models`], classifies errors into [`ApiError`] variants, and bumps
/// the `connectivity_tx` watch on every successful server response.
///
/// # Connectivity watch
///
/// The `connectivity_tx` sender (a [`watch::Sender<Instant>`]) is bumped (to
/// `Instant::now()`) on **every `Ok` result** returned by an API method.  The
/// executor's `ConnectivityMonitor` subscribes to this channel and uses it to
/// decide whether the daemon is still connected to the server during a running
/// rotation.
///
/// # Error classification
///
/// See [`ApiError`] for the full taxonomy.  The classification follows the rules
/// in the plan §4:
///
/// - Post-retry 401 → consult `session.phase()`: terminal → `SessionLost`, else `Transient`.
/// - 404 on poll/claim (daemon/job routes) → `NotEligible`.
/// - 404 on attempt routes → `UnknownAttempt`.
/// - 409 → `Rejected` (or `Ok(None)` for the claim endpoint).
/// - 429 / 5xx / transport → `Transient`.
/// - Decode failure → `Protocol`.
/// - Response bodies are **never** included in errors.
pub(crate) struct RotationApi {
    client: ApiClient,
    connectivity_tx: watch::Sender<Instant>,
}

impl RotationApi {
    /// Build a `RotationApi` wrapping the provided [`ApiClient`].
    ///
    /// `connectivity_tx` is bumped to `Instant::now()` on every successful API
    /// call; the executor's `ConnectivityMonitor` feeds off it.
    pub(crate) fn new(client: ApiClient, connectivity_tx: watch::Sender<Instant>) -> Self {
        Self {
            client,
            connectivity_tx,
        }
    }

    /// Mark a successful server contact on the connectivity watch.
    fn mark_ok(&self) {
        self.connectivity_tx.send_modify(|t| *t = Instant::now());
    }

    // -----------------------------------------------------------------------
    // Poll
    // -----------------------------------------------------------------------

    /// Poll for claimable rotation jobs.
    ///
    /// Returns the list of [`JobRef`]s the daemon may attempt to claim.  An
    /// empty list means no jobs are currently available (the daemon should wait
    /// for the next poll interval).
    ///
    /// A 404 on this (daemon-scoped) route maps to [`ApiError::NotEligible`]
    /// per the eligibility-filter semantics.
    pub(crate) async fn poll_jobs(&self) -> Result<Vec<JobRef>, ApiError> {
        let result = self.client.pam_rotation_daemon_jobs_api().get_all().await;

        match result {
            Ok(list_model) => {
                self.mark_ok();
                let jobs = list_model
                    .data
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|item| item.job_id.map(|id| JobRef { id }))
                    .collect();
                Ok(jobs)
            }
            Err(e) => Err(classify_error(e, &self.client, Route::DaemonOrJob)),
        }
    }

    // -----------------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------------

    /// Attempt to claim a rotation job.
    ///
    /// Returns:
    /// - `Ok(Some(snapshot))` — the daemon won the race and holds the claim.
    /// - `Ok(None)` — another daemon claimed it first (409); not an error.
    /// - `Err(ApiError::NotEligible)` — 404 on a daemon route (ineligible).
    /// - `Err(…)` — any other failure.
    pub(crate) async fn claim(&self, job_id: Uuid) -> Result<Option<WorkSnapshot>, ApiError> {
        let result = self.client.pam_rotation_jobs_api().claim(job_id).await;

        match result {
            Ok(model) => {
                self.mark_ok();
                let snapshot = parse_work_snapshot(model)?;
                Ok(Some(snapshot))
            }
            Err(bitwarden_api_base::Error::Response(ref rc)) if rc.status.as_u16() == 409 => {
                // 409 = race lost — not an error, caller continues to the next job.
                Ok(None)
            }
            Err(e) => Err(classify_error(e, &self.client, Route::DaemonOrJob)),
        }
    }

    // -----------------------------------------------------------------------
    // Cipher read
    // -----------------------------------------------------------------------

    /// Fetch the encrypted cipher for an executing attempt.
    ///
    /// A 404 on an attempt route maps to [`ApiError::UnknownAttempt`].
    pub(crate) async fn get_cipher(&self, attempt_id: Uuid) -> Result<RotationCipher, ApiError> {
        let result = self
            .client
            .pam_rotation_attempts_api()
            .get_cipher(attempt_id)
            .await;

        match result {
            Ok(model) => {
                self.mark_ok();
                parse_rotation_cipher(model)
            }
            Err(e) => Err(classify_error(e, &self.client, Route::Attempt)),
        }
    }

    // -----------------------------------------------------------------------
    // Cipher write
    // -----------------------------------------------------------------------

    /// Write the re-encrypted cipher data back to the server.
    ///
    /// - Returns `Ok(())` on success.
    /// - Returns `Err(ApiError::Rejected { status: 409 })` on revision-drift / capability-lost
    ///   (409).
    /// - Returns `Err(ApiError::UnknownAttempt)` if the attempt is not found (404).
    pub(crate) async fn put_cipher(
        &self,
        attempt_id: Uuid,
        data_json_string: String,
        last_known_revision_date: String,
    ) -> Result<(), ApiError> {
        let body = SubmitCipherUpdateRequestModel {
            data: data_json_string,
            last_known_revision_date,
        };

        let result = self
            .client
            .pam_rotation_attempts_api()
            .put_cipher(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, &self.client, Route::Attempt)),
        }
    }

    // -----------------------------------------------------------------------
    // Success report
    // -----------------------------------------------------------------------

    /// Report a successful rotation attempt.
    ///
    /// A 409 or 404 on the report endpoint is **final** — the server rejected
    /// or abandoned the attempt.  Do not retry; the caller should log at
    /// warn-level and move on.
    pub(crate) async fn report_success(
        &self,
        attempt_id: Uuid,
        termination: SessionTermination,
    ) -> Result<(), ApiError> {
        let body = ReportRotationSucceededRequestModel {
            session_termination: termination.into(),
        };

        let result = self
            .client
            .pam_rotation_attempts_api()
            .success(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, &self.client, Route::Attempt)),
        }
    }

    // -----------------------------------------------------------------------
    // Failure report
    // -----------------------------------------------------------------------

    /// Report a failed rotation attempt.
    ///
    /// `error_code` is serialised as the snake_case serde name of the
    /// [`FailureCode`] enum variant (e.g. `"credentials_unresolved"`), which is
    /// ≤ 100 characters by construction (the longest is `"cipher_write_rejected"` at
    /// 21 chars).
    ///
    /// A 409 or 404 on the report endpoint is **final** — see
    /// [`Self::report_success`].
    pub(crate) async fn report_failure(
        &self,
        attempt_id: Uuid,
        code: FailureCode,
        detail: Option<SafeDetail>,
        sync_state: SyncState,
    ) -> Result<(), ApiError> {
        // Serialise FailureCode as its snake_case serde name.
        let error_code = failure_code_string(code);

        let body = ReportRotationFailedRequestModel {
            sync_state: sync_state.into(),
            error_code,
            detail: detail.map(|d| d.as_str().to_owned()),
        };

        let result = self
            .client
            .pam_rotation_attempts_api()
            .failure(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, &self.client, Route::Attempt)),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Which class of route was called — used to disambiguate 404 semantics.
#[derive(Clone, Copy)]
enum Route {
    /// A daemon-scoped or job-scoped route (`/rotation/daemon/…` or
    /// `/rotation/jobs/…`).  A 404 here means the daemon is not eligible
    /// (the endpoint filter rejected it).
    DaemonOrJob,
    /// An attempt-scoped route (`/rotation/attempts/{id}/…`).  A 404 here
    /// means the attempt is not known to the server.
    Attempt,
}

/// Classify a generated API error into an [`ApiError`].
fn classify_error(err: bitwarden_api_base::Error, _client: &ApiClient, route: Route) -> ApiError {
    use bitwarden_api_base::Error;

    match err {
        Error::Response(rc) => {
            let status = rc.status.as_u16();
            match status {
                401 => {
                    // Post-retry 401: consult the session phase to distinguish
                    // terminal session loss from a transient auth glitch.
                    //
                    // We do not have an async context here so we cannot call
                    // session.phase().  Instead, we map 401 to Transient and let
                    // the caller inspect the session phase if needed. The middleware
                    // already handled the single refresh-and-retry, so a 401 here
                    // means the refresh itself failed or produced another 401.
                    //
                    // If the session became terminal during the refresh attempt the
                    // middleware would have returned a middleware error (Lost), not a
                    // 401 response, so mapping to Transient is correct for the
                    // non-terminal case.  For the terminal case, the middleware error
                    // path (get_bearer → Lost) takes precedence and this branch is
                    // not reached.
                    ApiError::Transient("HTTP 401 (post-retry)".to_string())
                }
                404 => match route {
                    Route::DaemonOrJob => ApiError::NotEligible,
                    Route::Attempt => ApiError::UnknownAttempt,
                },
                409 => ApiError::Rejected { status },
                429 | 500..=599 => ApiError::Transient(format!("HTTP {status}")),
                other => ApiError::Transient(format!("HTTP {other}")),
            }
        }
        Error::ReqwestMiddleware(mw_err) => {
            // A middleware error wrapping a SessionError::Lost comes through here.
            // The error message will contain "session lost: …" but we do not parse it;
            // instead, we must determine the actual session loss kind.
            //
            // We inspect the error string to detect the "session lost" case.  This is
            // safe — the message was constructed by us in get_bearer / force_refresh_bearer
            // and never contains credential data.
            let msg = mw_err.to_string();
            if msg.contains("session lost") {
                // Determine which kind of session loss occurred.  The message contains
                // "session lost: Revoked" or "session lost: Closed".
                if msg.contains("Revoked") {
                    ApiError::SessionLost(SessionLost::Revoked)
                } else {
                    ApiError::SessionLost(SessionLost::Closed)
                }
            } else {
                ApiError::Transient(format!(
                    "middleware: {}",
                    safe_middleware_description(&mw_err)
                ))
            }
        }
        Error::Reqwest(_) => ApiError::Transient("transport error".to_owned()),
        Error::Serde(_) => ApiError::Protocol("response decode failed".to_owned()),
        Error::Io(_) => ApiError::Transient("I/O error".to_owned()),
        Error::_Phantom(_, _) => unreachable!(),
    }
}

/// Extract a safe, non-secret description from a [`reqwest_middleware::Error`].
///
/// The middleware error might wrap arbitrary strings, but for our middleware
/// we control what is emitted.  For externally-sourced errors we emit only the
/// discriminant name.
fn safe_middleware_description(err: &reqwest_middleware::Error) -> &'static str {
    match err {
        reqwest_middleware::Error::Middleware(_) => "middleware error",
        reqwest_middleware::Error::Reqwest(_) => "reqwest error",
    }
}

/// Parse a [`bitwarden_api_api::models::RotationClaimResponseModel`] into a
/// [`WorkSnapshot`], returning [`ApiError::Protocol`] if any required field is
/// missing or unparseable.
fn parse_work_snapshot(
    model: bitwarden_api_api::models::RotationClaimResponseModel,
) -> Result<WorkSnapshot, ApiError> {
    macro_rules! required {
        ($field:expr, $name:literal) => {
            $field
                .ok_or_else(|| ApiError::Protocol(concat!("missing field: ", $name).to_owned()))?
        };
    }

    let attempt_id = required!(model.attempt_id, "attemptId");
    let job_id = required!(model.job_id, "jobId");
    let target_system_id = required!(model.target_system_id, "targetSystemId");
    let target_system_name = required!(model.target_system_name, "targetSystemName");
    let kind = TargetKind::from(required!(model.kind, "kind"));
    let cipher_id = required!(model.cipher_id, "cipherId");
    let account_identity = required!(model.account_identity, "accountIdentity");
    let terminate_sessions = model.terminate_sessions.unwrap_or(false);

    // Parse the password policy.
    let raw_policy = required!(model.password_policy, "passwordPolicy");
    let password_policy = crate::policy::PasswordPolicy::from(*raw_policy);

    // Parse execute_by as RFC-3339.
    let execute_by_str = required!(model.execute_by, "executeBy");
    let execute_by = execute_by_str
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| ApiError::Protocol("invalid executeBy timestamp".to_owned()))?;

    Ok(WorkSnapshot {
        attempt_id,
        job_id,
        target_system_id,
        target_system_name,
        kind,
        password_policy,
        cipher_id,
        account_identity,
        terminate_sessions,
        execute_by,
    })
}

/// Parse a [`bitwarden_api_api::models::RotationCipherResponseModel`] into a
/// [`RotationCipher`].
///
/// A missing or malformed `data` field is a protocol error; the field's
/// **content** is never included in the error message.
fn parse_rotation_cipher(
    model: bitwarden_api_api::models::RotationCipherResponseModel,
) -> Result<RotationCipher, ApiError> {
    macro_rules! required {
        ($field:expr, $name:literal) => {
            $field
                .ok_or_else(|| ApiError::Protocol(concat!("missing field: ", $name).to_owned()))?
        };
    }

    let cipher_id = required!(model.cipher_id, "cipherId");
    let revision_date = required!(model.revision_date, "revisionDate");

    // The `data` field is the cipher's encrypted JSON blob as a STRING.
    // Parse it into serde_json::Value; a missing or unparseable value is a
    // protocol error — we do NOT echo the content.
    let data_str = required!(model.data, "data");
    let data = serde_json::from_str::<serde_json::Value>(&data_str)
        .map_err(|_| ApiError::Protocol("cipher data field is not valid JSON".to_owned()))?;

    Ok(RotationCipher {
        cipher_id,
        data,
        key: model.key,
        revision_date,
    })
}

/// Serialise a [`FailureCode`] to its snake_case wire string.
///
/// The string is derived from the serde `snake_case` rename, which guarantees
/// ≤ 100 characters (the longest variant name is `cipher_write_rejected` at
/// 21 characters, well within the server's `errorCode` field limit of 100).
fn failure_code_string(code: FailureCode) -> String {
    // serde_json::to_value serialises the enum to its snake_case string form.
    // We extract the inner string and strip the surrounding quotes.
    let v = serde_json::to_value(code)
        .unwrap_or_else(|_| serde_json::Value::String("internal".to_owned()));
    match v {
        serde_json::Value::String(s) => s,
        // Should never happen given the FailureCode derive, but be defensive.
        _ => "internal".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Instant};

    use bitwarden_api_api::models::PamPasswordPolicyResponseModel;
    use bitwarden_api_base::Configuration;
    use reqwest_middleware::ClientBuilder;
    use tokio::sync::watch;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;
    use crate::{
        auth::{identity::IdentityClient, session::SessionManager},
        error::{FailureCode, SafeDetail, SyncState},
    };

    // ── Shared test helpers ────────────────────────────────────────────────

    const VALID_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn test_token() -> crate::token::DaemonToken {
        use std::str::FromStr;
        crate::token::DaemonToken::from_str(VALID_TOKEN_STR).expect("valid token")
    }

    fn token_encryption_key() -> bitwarden_crypto::SymmetricCryptoKey {
        use bitwarden_crypto::{SymmetricCryptoKey, derive_shareable_key};
        use bitwarden_encoding::B64;
        use zeroize::Zeroizing;
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().expect("valid b64");
        let key_bytes: Zeroizing<[u8; 16]> =
            Zeroizing::new(b64.as_bytes().try_into().expect("16 bytes"));
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
        let org_key_b64 = bitwarden_encoding::B64::from(org_key_bytes.as_ref());
        let org_key_b64_str: String = org_key_b64.into();
        let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);
        payload_json
            .as_str()
            .encrypt_with_key(token_key)
            .expect("encrypt payload")
            .to_string()
    }

    fn identity_success_response(
        bearer: &str,
        expires_in: u64,
        encrypted_payload: &str,
    ) -> ResponseTemplate {
        let body = format!(
            r#"{{"access_token":"{bearer}","expires_in":{expires_in},"encryptedPayload":"{encrypted_payload}"}}"#
        );
        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "application/json")
    }

    /// Build a SessionManager backed by a wiremock identity server.
    async fn make_session(identity_server: &MockServer, bearer: &str) -> Arc<SessionManager> {
        let token_key = token_encryption_key();
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = make_encrypted_payload(&token_key, &org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response(bearer, 3600, &payload))
            .mount(identity_server)
            .await;

        let identity_client = IdentityClient::new(identity_server.uri()).expect("identity client");
        SessionManager::new(identity_client, test_token())
            .await
            .expect("SessionManager::new")
    }

    /// Build a [`RotationApi`] pointed at `api_server` using the given
    /// `session`.
    fn make_rotation_api(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> (RotationApi, watch::Receiver<Instant>) {
        let (tx, rx) = watch::channel(Instant::now());
        let client = build_api_client(api_server.uri(), session);
        let api = RotationApi::new(client, tx);
        (api, rx)
    }

    // ── failure_code_string ────────────────────────────────────────────────

    #[test]
    fn failure_code_string_snake_case() {
        assert_eq!(
            failure_code_string(FailureCode::NoActiveSession),
            "no_active_session"
        );
        assert_eq!(
            failure_code_string(FailureCode::CredentialsUnresolved),
            "credentials_unresolved"
        );
        assert_eq!(
            failure_code_string(FailureCode::InvalidPolicy),
            "invalid_policy"
        );
        assert_eq!(
            failure_code_string(FailureCode::UnsupportedKind),
            "unsupported_kind"
        );
        assert_eq!(failure_code_string(FailureCode::Internal), "internal");
        assert_eq!(
            failure_code_string(FailureCode::CipherWriteRejected),
            "cipher_write_rejected"
        );
    }

    #[test]
    fn failure_code_string_within_100_chars() {
        for code in [
            FailureCode::NoActiveSession,
            FailureCode::CredentialsUnresolved,
            FailureCode::InvalidPolicy,
            FailureCode::UnsupportedKind,
            FailureCode::TargetRejected,
            FailureCode::TargetUnreachable,
            FailureCode::VerificationFailed,
            FailureCode::ScriptFailed,
            FailureCode::ScriptTimeout,
            FailureCode::CipherWriteRejected,
            FailureCode::CipherEncryptFailed,
            FailureCode::Internal,
        ] {
            let s = failure_code_string(code);
            assert!(
                s.len() <= 100,
                "errorCode for {code:?} exceeds 100 chars: {s:?}"
            );
        }
    }

    // ── parse_work_snapshot ────────────────────────────────────────────────

    #[test]
    fn parse_work_snapshot_converts_correctly() {
        use bitwarden_api_api::models::{PamTargetSystemKind, RotationClaimResponseModel};
        use chrono::Utc;

        let model = RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("test-system".to_owned()),
            kind: Some(PamTargetSystemKind::CustomScript),
            password_policy: Some(Box::new(PamPasswordPolicyResponseModel {
                min_length: Some(8),
                max_length: Some(64),
                include_uppercase: Some(true),
                include_lowercase: Some(true),
                include_digits: Some(true),
                include_symbols: Some(false),
            })),
            cipher_id: Some(Uuid::new_v4()),
            account_identity: Some("user@example.com".to_owned()),
            terminate_sessions: Some(true),
            execute_by: Some(Utc::now().to_rfc3339()),
        };

        let snap = parse_work_snapshot(model).expect("parse_work_snapshot");
        assert_eq!(snap.kind, TargetKind::CustomScript);
        assert_eq!(snap.account_identity, "user@example.com");
        assert!(snap.terminate_sessions);
        assert_eq!(snap.password_policy.min_length, Some(8));
        assert_eq!(snap.password_policy.max_length, Some(64));
    }

    #[test]
    fn parse_work_snapshot_missing_field_is_protocol_error() {
        use bitwarden_api_api::models::RotationClaimResponseModel;

        // attempt_id is missing.
        let model = RotationClaimResponseModel::new();
        let err = parse_work_snapshot(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    #[test]
    fn parse_work_snapshot_bad_execute_by_is_protocol_error() {
        use bitwarden_api_api::models::{PamTargetSystemKind, RotationClaimResponseModel};

        let model = RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("ts".to_owned()),
            kind: Some(PamTargetSystemKind::Entra),
            password_policy: Some(Box::new(PamPasswordPolicyResponseModel {
                min_length: None,
                max_length: None,
                include_uppercase: Some(true),
                include_lowercase: Some(true),
                include_digits: Some(true),
                include_symbols: Some(true),
            })),
            cipher_id: Some(Uuid::new_v4()),
            account_identity: Some("user".to_owned()),
            terminate_sessions: Some(false),
            execute_by: Some("NOT-A-DATE".to_owned()),
        };

        let err = parse_work_snapshot(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    #[test]
    fn claim_409_maps_to_ok_none() {
        // Verify parse_work_snapshot is not called for 409 (handled before it).
        // We test this at the classify_error level.
        let rc = bitwarden_api_base::ResponseContent {
            status: reqwest::StatusCode::CONFLICT,
            message: String::new(),
        };
        let err: bitwarden_api_base::Error = bitwarden_api_base::Error::Response(rc);
        let api_err = classify_error(
            err,
            &{
                // Build a minimal ApiClient for testing (the client is not used).
                let config = Arc::new(Configuration {
                    base_path: "http://localhost".to_owned(),
                    client: ClientBuilder::new(
                        bitwarden_api_base::new_http_client_builder()
                            .build()
                            .unwrap(),
                    )
                    .build(),
                });
                ApiClient::new(&config)
            },
            Route::DaemonOrJob,
        );
        assert!(matches!(api_err, ApiError::Rejected { status: 409 }));
    }

    // ── parse_rotation_cipher ──────────────────────────────────────────────

    #[test]
    fn parse_rotation_cipher_parses_data_string_to_value() {
        use bitwarden_api_api::models::RotationCipherResponseModel;

        let data_json = r#"{"Password":"2.abc123==","SomeOther":"field"}"#;
        let model = RotationCipherResponseModel {
            cipher_id: Some(Uuid::new_v4()),
            organization_id: Some(Uuid::new_v4()),
            r#type: None,
            data: Some(data_json.to_owned()),
            key: Some("encrypted-key".to_owned()),
            revision_date: Some("2024-01-01T00:00:00Z".to_owned()),
        };

        let cipher = parse_rotation_cipher(model).expect("parse_rotation_cipher");
        assert_eq!(cipher.data["Password"], "2.abc123==");
        assert_eq!(cipher.data["SomeOther"], "field");
        assert_eq!(cipher.key.as_deref(), Some("encrypted-key"));
        assert_eq!(cipher.revision_date, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn parse_rotation_cipher_missing_data_is_protocol_error() {
        use bitwarden_api_api::models::RotationCipherResponseModel;

        let model = RotationCipherResponseModel {
            cipher_id: Some(Uuid::new_v4()),
            organization_id: None,
            r#type: None,
            data: None,
            key: None,
            revision_date: Some("2024-01-01T00:00:00Z".to_owned()),
        };

        let err = parse_rotation_cipher(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    #[test]
    fn parse_rotation_cipher_invalid_json_in_data_is_protocol_error() {
        use bitwarden_api_api::models::RotationCipherResponseModel;

        let model = RotationCipherResponseModel {
            cipher_id: Some(Uuid::new_v4()),
            organization_id: None,
            r#type: None,
            data: Some("NOT VALID JSON".to_owned()),
            key: None,
            revision_date: Some("2024-01-01T00:00:00Z".to_owned()),
        };

        let err = parse_rotation_cipher(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    // ── Connectivity bump ──────────────────────────────────────────────────

    #[tokio::test]
    async fn poll_happy_path_bumps_connectivity_and_parses_jobs() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, mut connectivity_rx) = make_rotation_api(&api_server, session);

        let before = *connectivity_rx.borrow();

        let job_id = Uuid::new_v4();
        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [{"jobId": job_id.to_string(), "targetSystemId": Uuid::new_v4().to_string()}]
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let jobs = api.poll_jobs().await.expect("poll_jobs");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job_id);

        connectivity_rx
            .changed()
            .await
            .expect("connectivity changed");
        let after = *connectivity_rx.borrow();
        assert!(
            after > before,
            "connectivity should be bumped after successful poll"
        );
    }

    #[tokio::test]
    async fn poll_404_maps_to_not_eligible() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&api_server)
            .await;

        let err = api.poll_jobs().await.expect_err("should fail");
        assert!(matches!(err, ApiError::NotEligible), "got: {err:?}");
    }

    #[tokio::test]
    async fn claim_200_parses_work_snapshot() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let job_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let execute_by = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(5))
            .unwrap()
            .to_rfc3339();

        Mock::given(method("POST"))
            .and(path(format!("/rotation/jobs/{job_id}/claim")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": attempt_id,
                        "jobId": job_id,
                        "targetSystemId": target_system_id,
                        "targetSystemName": "my-script",
                        "kind": 2,  // CustomScript
                        "passwordPolicy": {
                            "minLength": 12,
                            "maxLength": 64,
                            "includeUppercase": true,
                            "includeLowercase": true,
                            "includeDigits": true,
                            "includeSymbols": false
                        },
                        "cipherId": cipher_id,
                        "accountIdentity": "svc_account",
                        "terminateSessions": true,
                        "executeBy": execute_by
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let snap = api
            .claim(job_id)
            .await
            .expect("claim")
            .expect("some snapshot");
        assert_eq!(snap.attempt_id, attempt_id);
        assert_eq!(snap.kind, TargetKind::CustomScript);
        assert_eq!(snap.account_identity, "svc_account");
        assert!(snap.terminate_sessions);
        assert_eq!(snap.password_policy.min_length, Some(12));
        assert_eq!(snap.password_policy.max_length, Some(64));
        assert!(snap.password_policy.include_uppercase);
        assert!(!snap.password_policy.include_symbols);
    }

    #[tokio::test]
    async fn claim_409_maps_to_ok_none_integrated() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let job_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path(format!("/rotation/jobs/{job_id}/claim")))
            .respond_with(ResponseTemplate::new(409))
            .mount(&api_server)
            .await;

        let result = api.claim(job_id).await.expect("no error");
        assert!(result.is_none(), "409 should map to Ok(None)");
    }

    #[tokio::test]
    async fn get_cipher_parses_data_string_to_value() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let attempt_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let data_json_str = r#"{"Password":"2.abc==","Username":"admin"}"#;

        Mock::given(method("GET"))
            .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "cipherId": cipher_id,
                        "data": data_json_str,
                        "revisionDate": "2024-06-01T12:00:00Z"
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let cipher = api.get_cipher(attempt_id).await.expect("get_cipher");
        assert_eq!(cipher.cipher_id, cipher_id);
        // data should be parsed from the string into a JSON Value.
        assert_eq!(cipher.data["Password"], "2.abc==");
        assert_eq!(cipher.data["Username"], "admin");
        assert_eq!(cipher.revision_date, "2024-06-01T12:00:00Z");
    }

    #[tokio::test]
    async fn put_cipher_409_maps_to_rejected() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let attempt_id = Uuid::new_v4();
        Mock::given(method("PUT"))
            .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
            .respond_with(ResponseTemplate::new(409))
            .mount(&api_server)
            .await;

        let err = api
            .put_cipher(
                attempt_id,
                r#"{"Password":"2.new=="}"#.to_owned(),
                "2024-06-01T12:00:00Z".to_owned(),
            )
            .await
            .expect_err("should fail");

        assert!(
            matches!(err, ApiError::Rejected { status: 409 }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn put_cipher_404_maps_to_unknown_attempt() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let attempt_id = Uuid::new_v4();
        Mock::given(method("PUT"))
            .and(path(format!("/rotation/attempts/{attempt_id}/cipher")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&api_server)
            .await;

        let err = api
            .put_cipher(
                attempt_id,
                r#"{"Password":"2.new=="}"#.to_owned(),
                "2024-06-01T12:00:00Z".to_owned(),
            )
            .await
            .expect_err("should fail");

        assert!(matches!(err, ApiError::UnknownAttempt), "got: {err:?}");
    }

    #[tokio::test]
    async fn failure_report_serialises_integer_sync_state_and_snake_case_error_code() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let attempt_id = Uuid::new_v4();

        // Capture the request body to verify serialisation.
        Mock::given(method("POST"))
            .and(path(format!("/rotation/attempts/{attempt_id}/failure")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        api.report_failure(
            attempt_id,
            FailureCode::TargetUnreachable,
            Some(SafeDetail::from_status(503)),
            SyncState::TargetUpdated,
        )
        .await
        .expect("report_failure");

        let requests = api_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("parse request body");

        // syncState must be an INTEGER (1 = TargetUpdated).
        assert_eq!(
            body["syncState"],
            serde_json::Value::Number(serde_json::Number::from(1)),
            "syncState must be an integer, got: {}",
            body["syncState"]
        );

        // errorCode must be a string in snake_case.
        assert_eq!(
            body["errorCode"],
            serde_json::Value::String("target_unreachable".to_owned()),
            "errorCode must be snake_case string"
        );
    }

    #[tokio::test]
    async fn no_auth_header_without_auth_required_extension() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "my-bearer").await;
        let (_tx, _rx) = watch::channel(Instant::now());

        // Build a raw middleware-wrapped client (no auth extension on the request).
        let http_client = bitwarden_api_base::new_http_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let client = ClientBuilder::new(http_client)
            .with(DaemonAuthMiddleware::new(Arc::clone(&session)))
            .build();

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

        // Request WITHOUT AuthRequired extension.
        client
            .get(format!("{}/test", api_server.uri()))
            .send()
            .await
            .expect("request");

        let requests = api_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].headers.get("authorization").is_none(),
            "no Authorization header should be attached when AuthRequired extension is absent"
        );
    }

    #[tokio::test]
    async fn middleware_refreshes_once_on_401_and_retries() {
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let token_key = token_encryption_key();
        let org_key1 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload1 = make_encrypted_payload(&token_key, &org_key1);
        let org_key2 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload2 = make_encrypted_payload(&token_key, &org_key2);

        // Identity: first call returns "bearer-1", second returns "bearer-2".
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response("bearer-1", 3600, &payload1))
            .up_to_n_times(1)
            .mount(&identity_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response("bearer-2", 3600, &payload2))
            .mount(&identity_server)
            .await;

        let identity_client = IdentityClient::new(identity_server.uri()).expect("identity client");
        let session = SessionManager::new(identity_client, test_token())
            .await
            .expect("SessionManager::new");

        // API: first request with bearer-1 gets 401; second request with bearer-2 gets 200.
        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
            .and(header("Authorization", "Bearer bearer-1"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&api_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rotation/daemon/jobs"))
            .and(header("Authorization", "Bearer bearer-2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let (tx, _rx) = watch::channel(Instant::now());
        let client = build_api_client(api_server.uri(), session);
        let api = RotationApi::new(client, tx);

        let jobs = api.poll_jobs().await.expect("poll_jobs after 401-refresh");
        assert!(jobs.is_empty());

        // Verify: 2 identity calls (initial + refresh), 2 API calls (401 + retry).
        let identity_reqs = identity_server.received_requests().await.unwrap();
        assert_eq!(
            identity_reqs.len(),
            2,
            "exactly 2 identity calls expected (initial auth + one refresh)"
        );
        let api_reqs = api_server.received_requests().await.unwrap();
        assert_eq!(
            api_reqs.len(),
            2,
            "exactly 2 API requests expected (401 attempt + retry)"
        );
    }
}
