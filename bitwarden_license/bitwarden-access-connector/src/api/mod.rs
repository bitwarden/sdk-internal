//! HTTP API client wrappers for the Bitwarden server's PAM rotation endpoints.
//!
//! [`build_sdk_client`] assembles the client the connector runs on; [`RotationApi`] reaches
//! through its configurations, mapping calls into domain types.

pub(crate) mod models;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_api_api::{
    apis::AuthRequired,
    models::{
        ReportRotationFailedRequestModel, ReportRotationSucceededRequestModel,
        SubmitCipherUpdateRequestModel,
    },
};
use bitwarden_core::{Client, ClientBuilder, ClientSettings, client::internal::ApiConfigurations};
use models::{ApiError, JobRef, RotationCipher, WorkSnapshot};
use reqwest_middleware::{Middleware, Next};
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    auth::{
        session::{SessionError, SessionLost, SessionManager},
        token_handler::AccessConnectorTokenHandler,
    },
    error::{FailureCode, SafeDetail, SessionTermination, SyncState},
};

/// [`reqwest_middleware::Middleware`] that attaches the connector bearer token and retries one 401
/// after a forced refresh. Unlike bitwarden-auth's middleware, it fails on session loss instead of
/// sending the request without a token. Session loss is signalled by the typed [`SessionError`],
/// not by the error message.
pub(crate) struct AccessConnectorAuthMiddleware {
    handler: AccessConnectorTokenHandler,
}

impl AccessConnectorAuthMiddleware {
    pub(crate) fn new(handler: AccessConnectorTokenHandler) -> Self {
        Self { handler }
    }

    /// Core builds this middleware before startup has a session; a request in that window fails
    /// rather than going out unauthenticated.
    fn session(&self) -> Result<Arc<SessionManager>, reqwest_middleware::Error> {
        self.handler.session().ok_or_else(|| {
            tracing::error!("authenticated request issued before the session was installed");
            reqwest_middleware::Error::Middleware(anyhow::Error::new(SessionNotInstalledError))
        })
    }

    async fn get_bearer(&self) -> Result<String, reqwest_middleware::Error> {
        self.session()?
            .bearer(None)
            .await
            .map_err(session_error_to_middleware)
    }

    async fn force_refresh_bearer(&self, stale: &str) -> Result<String, reqwest_middleware::Error> {
        self.session()?
            .force_refresh(stale, None)
            .await
            .map_err(session_error_to_middleware)
    }
}

/// A request needed a bearer before [`AccessConnectorTokenHandler::set_session`] ran.
#[derive(Debug)]
pub(crate) struct SessionNotInstalledError;

impl std::fmt::Display for SessionNotInstalledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session not installed")
    }
}

impl std::error::Error for SessionNotInstalledError {}

#[async_trait::async_trait]
impl Middleware for AccessConnectorAuthMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // The generated API opts into auth via the AuthRequired::Bearer extension.
        let auth_required = matches!(ext.get::<AuthRequired>(), Some(AuthRequired::Bearer));

        let used_token: Option<String> = if auth_required {
            let token = self.get_bearer().await?;
            attach_bearer_header(&mut req, &token);
            Some(token)
        } else {
            None
        };

        // Clone before `run` consumes the request; a streaming body cannot be cloned and gets no
        // retry.
        let req_clone = req.try_clone();

        let response = next.clone().run(req, ext).await?;

        if auth_required
            && let Some(mut cloned) = req_clone
            && response.status() == http::StatusCode::UNAUTHORIZED
        {
            tracing::info!("connector API: 401 received, refreshing token and retrying");

            let stale = used_token.as_deref().unwrap_or("");
            let new_token = self.force_refresh_bearer(stale).await?;
            attach_bearer_header(&mut cloned, &new_token);

            return next.run(cloned, ext).await;
        }

        Ok(response)
    }
}

fn attach_bearer_header(req: &mut reqwest::Request, token: &str) {
    let value = match format!("Bearer {token}").parse::<http::HeaderValue>() {
        Ok(v) => v,
        Err(e) => {
            // The token has a character invalid in a header value. Proceed without it; the
            // server's 401 surfaces the error through the retry path.
            tracing::warn!("connector API: cannot format bearer token as header value: {e}");
            return;
        }
    };
    req.headers_mut().insert(http::header::AUTHORIZATION, value);
}

/// Wrap a [`SessionError`] so [`session_loss`] can downcast it back out; `reqwest_middleware`
/// and `anyhow` both pass the concrete type through untouched.
fn session_error_to_middleware(err: SessionError) -> reqwest_middleware::Error {
    reqwest_middleware::Error::Middleware(anyhow::Error::new(err))
}

/// A black-holed connection must not starve the heartbeat past the server's
/// `AccessConnectorOfflineAfter`.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Applies [`REQUEST_TIMEOUT`] to a whole request.
///
/// Applies [`REQUEST_TIMEOUT`] to a whole request. Neither `new_http_client_builder` nor core's
/// `ClientBuilder::build` sets one, so a client built through [`bitwarden_core::Client`] needs this
/// passed as middleware.
pub(crate) struct TimeoutMiddleware {
    timeout: Duration,
}

impl TimeoutMiddleware {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait::async_trait]
impl Middleware for TimeoutMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        tokio::time::timeout(self.timeout, next.run(req, ext))
            .await
            .unwrap_or_else(|_| {
                Err(reqwest_middleware::Error::Middleware(anyhow::Error::new(
                    RequestTimedOutError,
                )))
            })
    }
}

/// A request exceeded [`REQUEST_TIMEOUT`].
#[derive(Debug)]
pub(crate) struct RequestTimedOutError;

impl std::fmt::Display for RequestTimedOutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request timed out")
    }
}

impl std::error::Error for RequestTimedOutError {}

/// Builds the SDK client the connector runs against, plus the handler that carries its session
/// once startup has one.
///
/// [`TimeoutMiddleware`] is load-bearing twice over: core sets no per-request timeout, and it only
/// disables redirect-following when the extra-middleware vec is non-empty (the auth middleware does
/// not count). Passing none would drop the timeout and start following redirects, so
/// `request_times_out_rather_than_hanging` and `does_not_follow_a_cross_host_redirect` guard both.
///
/// Redirects are refused not because they would leak the bearer (reqwest strips `Authorization`
/// when the host, port or scheme changes) but because these endpoints never legitimately redirect.
/// Following one would send the request to a host the server named, read that host's reply as the
/// API's, and on a 307 forward the encrypted cipher body.
///
/// Chained outermost, the timeout also bounds token renewal, so the heartbeat cannot stall past
/// `AccessConnectorOfflineAfter` whatever it is waiting on.
pub(crate) fn build_sdk_client(
    api_url: String,
    identity_url: String,
    timeout: Duration,
) -> (Client, AccessConnectorTokenHandler) {
    let handler = AccessConnectorTokenHandler::default();

    let client = ClientBuilder::new()
        .with_settings(ClientSettings {
            api_url,
            identity_url,
            ..Default::default()
        })
        .with_token_handler(Arc::new(handler.clone()))
        .with_middleware(vec![Arc::new(TimeoutMiddleware::new(timeout))])
        .build();

    (client, handler)
}

/// Domain-typed wrapper around the generated PAM rotation API clients.
///
/// Every successful response bumps `connectivity_tx`, which the rotation gate reads to pause
/// target-side steps while the server is unreachable.
pub(crate) struct RotationApi {
    api_configurations: Arc<ApiConfigurations>,
    connectivity_tx: watch::Sender<Instant>,
}

impl RotationApi {
    /// Reaches through the client's shared configurations at the point of use, as `SyncClient`
    /// does: `ApiClient` is not `Clone`, and rebuilding one would construct ~85 sub-API clients
    /// the client already has.
    pub(crate) fn new(
        api_configurations: Arc<ApiConfigurations>,
        connectivity_tx: watch::Sender<Instant>,
    ) -> Self {
        Self {
            api_configurations,
            connectivity_tx,
        }
    }

    fn mark_ok(&self) {
        self.connectivity_tx.send_modify(|t| *t = Instant::now());
    }

    /// Poll for claimable rotation jobs. A 404 maps to [`ApiError::NotEligible`].
    pub(crate) async fn poll_jobs(&self) -> Result<Vec<JobRef>, ApiError> {
        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_jobs_api()
            .get_all()
            .await;

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
            Err(e) => Err(classify_error(e, Route::AccessConnectorOrJob)),
        }
    }

    /// Attempt to claim a rotation job.
    ///
    /// `Ok(None)` means another connector won the race (409). A 404 maps to
    /// [`ApiError::NotEligible`].
    pub(crate) async fn claim(&self, job_id: Uuid) -> Result<Option<WorkSnapshot>, ApiError> {
        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_jobs_api()
            .claim(job_id)
            .await;

        match result {
            Ok(model) => {
                self.mark_ok();
                let snapshot = parse_work_snapshot(model)?;
                Ok(Some(snapshot))
            }
            Err(bitwarden_api_base::Error::Response(ref rc)) if rc.status.as_u16() == 409 => {
                Ok(None)
            }
            Err(e) => Err(classify_error(e, Route::AccessConnectorOrJob)),
        }
    }

    /// Fetch the encrypted cipher for an executing attempt. A 404 maps to
    /// [`ApiError::UnknownAttempt`].
    pub(crate) async fn get_cipher(&self, attempt_id: Uuid) -> Result<RotationCipher, ApiError> {
        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .get_cipher(attempt_id)
            .await;

        match result {
            Ok(model) => {
                self.mark_ok();
                parse_rotation_cipher(model)
            }
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }

    /// Write the re-encrypted cipher data back to the server.
    ///
    /// A 409 means revision-drift or capability-lost; a 404 means the attempt is unknown.
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
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .put_cipher(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }

    /// Report a successful rotation attempt.
    ///
    /// A 409 or 404 here is final: the server rejected or abandoned the attempt.
    /// Do not retry; log at warn-level and move on.
    pub(crate) async fn report_success(
        &self,
        attempt_id: Uuid,
        termination: SessionTermination,
    ) -> Result<(), ApiError> {
        let body = ReportRotationSucceededRequestModel {
            session_termination: termination.into(),
        };

        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .success(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }

    /// Report a failed rotation attempt. A 409 or 404 here is final, as in
    /// [`Self::report_success`].
    pub(crate) async fn report_failure(
        &self,
        attempt_id: Uuid,
        code: FailureCode,
        detail: Option<SafeDetail>,
        sync_state: SyncState,
    ) -> Result<(), ApiError> {
        let error_code = failure_code_string(code);

        let body = ReportRotationFailedRequestModel {
            sync_state: sync_state.into(),
            error_code,
            detail: detail.map(|d| d.as_str().to_owned()),
        };

        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .failure(attempt_id, body)
            .await;

        match result {
            Ok(()) => {
                self.mark_ok();
                Ok(())
            }
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }
}

/// Route class, for disambiguating 404 semantics.
#[derive(Clone, Copy)]
enum Route {
    /// `/access-connectors/rotation/jobs` and `jobs/{id}/claim`, where a 404 means the connector is
    /// not eligible.
    AccessConnectorOrJob,
    /// `/access-connectors/rotation/attempts/{id}/…`, where a 404 means the server does not know
    /// the attempt.
    Attempt,
}

fn classify_error(err: bitwarden_api_base::Error, route: Route) -> ApiError {
    use bitwarden_api_base::Error;

    match err {
        Error::Response(rc) => {
            let status = rc.status.as_u16();
            match status {
                401 => {
                    // No async context to call session.phase() here, so a post-retry 401
                    // maps to Transient; a terminal session loss surfaces earlier instead.
                    ApiError::Transient("HTTP 401 (post-retry)".to_string())
                }
                404 => match route {
                    Route::AccessConnectorOrJob => ApiError::NotEligible,
                    Route::Attempt => ApiError::UnknownAttempt,
                },
                409 => ApiError::Rejected { status },
                429 | 500..=599 => ApiError::Transient(format!("HTTP {status}")),
                other => ApiError::Transient(format!("HTTP {other}")),
            }
        }
        Error::ReqwestMiddleware(mw_err) => match session_loss(&mw_err) {
            Some(lost) => ApiError::SessionLost(lost),
            None => ApiError::Transient(format!(
                "middleware: {}",
                safe_middleware_description(&mw_err)
            )),
        },
        Error::Reqwest(_) => ApiError::Transient("transport error".to_owned()),
        Error::Serde(_) => ApiError::Protocol("response decode failed".to_owned()),
        Error::Io(_) => ApiError::Transient("I/O error".to_owned()),
    }
}

/// Recover a terminal [`SessionLost`] from a middleware error; anything else — a transient
/// renewal failure, another middleware's error — yields `None`.
fn session_loss(err: &reqwest_middleware::Error) -> Option<SessionLost> {
    let reqwest_middleware::Error::Middleware(inner) = err else {
        return None;
    };

    match inner.downcast_ref::<SessionError>()? {
        SessionError::Lost(lost) => Some(*lost),
        SessionError::Transient(_) => None,
    }
}

/// Names only the variant of a [`reqwest_middleware::Error`], since its message can wrap arbitrary
/// strings.
fn safe_middleware_description(err: &reqwest_middleware::Error) -> &'static str {
    match err {
        reqwest_middleware::Error::Middleware(_) => "middleware error",
        reqwest_middleware::Error::Reqwest(_) => "reqwest error",
    }
}

/// Parse a [`bitwarden_api_api::models::RotationClaimResponseModel`] into a
/// [`WorkSnapshot`]; a missing or unparseable required field is [`ApiError::Protocol`].
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
    let cipher_id = required!(model.cipher_id, "cipherId");

    let execute_by_str = required!(model.execute_by, "executeBy");
    let execute_by = execute_by_str
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| ApiError::Protocol("invalid executeBy timestamp".to_owned()))?;

    // The sealed halves are not `required!`: a missing one is rejected by `executor::verify`.
    Ok(WorkSnapshot {
        attempt_id,
        job_id,
        target_system_id,
        target_system_name,
        cipher_id,
        target_system_sealed_data: model.target_system_sealed_data,
        target_system_wrapped_key: model.target_system_wrapped_key,
        rotation_config_sealed_data: model.rotation_config_sealed_data,
        rotation_config_wrapped_key: model.rotation_config_wrapped_key,
        execute_by,
    })
}

/// Parse a [`bitwarden_api_api::models::RotationCipherResponseModel`] into a
/// [`RotationCipher`]. A missing or malformed `data` field is a protocol error that never includes
/// the field's content.
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

/// Serialise a [`FailureCode`] to its snake_case serde name. The server caps `errorCode` at 100
/// characters, far above the longest variant name.
fn failure_code_string(code: FailureCode) -> String {
    let v = serde_json::to_value(code)
        .unwrap_or_else(|_| serde_json::Value::String("internal".to_owned()));
    match v {
        serde_json::Value::String(s) => s,
        // Unreachable: FailureCode serialises unit variants as strings.
        _ => "internal".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Instant};

    use bitwarden_crypto::KeyStore;
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
        test_support::{access_token_tagged, encrypted_payload_for, test_org_id, test_token},
    };

    /// `bearer` is a short tag, expanded to a real JWT so the `organization` claim parses.
    fn identity_success_response(
        bearer: &str,
        expires_in: u64,
        encrypted_payload: &str,
    ) -> ResponseTemplate {
        let bearer = access_token_tagged(test_org_id(), bearer);
        let body = format!(
            r#"{{"access_token":"{bearer}","expires_in":{expires_in},"encrypted_payload":"{encrypted_payload}"}}"#
        );
        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "application/json")
    }

    async fn make_session(identity_server: &MockServer, bearer: &str) -> Arc<SessionManager> {
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response(bearer, 3600, &payload))
            .mount(identity_server)
            .await;

        let identity_client = IdentityClient::new(identity_server.uri()).expect("identity client");
        SessionManager::new(identity_client, test_token(), KeyStore::default())
            .await
            .expect("SessionManager::new")
    }

    /// A handler holding `session`, as startup leaves it.
    fn handler_for(session: Arc<SessionManager>) -> AccessConnectorTokenHandler {
        let handler = AccessConnectorTokenHandler::default();
        handler.set_session(session);
        handler
    }

    /// A [`RotationApi`] over the same client stack production builds.
    fn make_rotation_api(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> (RotationApi, watch::Receiver<Instant>) {
        let (tx, rx) = watch::channel(Instant::now());
        let api = RotationApi::new(api_configurations_for(api_server, session), tx);
        (api, rx)
    }

    /// The client's [`ApiConfigurations`], with `session` installed on its handler.
    fn api_configurations_for(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> Arc<ApiConfigurations> {
        let (client, handler) = build_sdk_client(
            api_server.uri(),
            "http://identity.invalid".to_owned(),
            REQUEST_TIMEOUT,
        );
        handler.set_session(session);
        client.internal.get_api_configurations()
    }

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
        assert_eq!(
            failure_code_string(FailureCode::SealedDataRejected),
            "sealed_data_rejected"
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
            FailureCode::SealedDataRejected,
            FailureCode::Internal,
        ] {
            let s = failure_code_string(code);
            assert!(
                s.len() <= 100,
                "errorCode for {code:?} exceeds 100 chars: {s:?}"
            );
        }
    }

    #[test]
    fn parse_work_snapshot_converts_correctly() {
        use bitwarden_api_api::models::RotationClaimResponseModel;
        use chrono::Utc;

        let model = RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("test-system".to_owned()),
            target_system_sealed_data: Some("opaque-target-blob".to_owned()),
            target_system_wrapped_key: Some("opaque-target-key".to_owned()),
            cipher_id: Some(Uuid::new_v4()),
            rotation_config_sealed_data: Some("opaque-config-blob".to_owned()),
            rotation_config_wrapped_key: Some("opaque-config-key".to_owned()),
            execute_by: Some(Utc::now().to_rfc3339()),
        };

        let snap = parse_work_snapshot(model).expect("parse_work_snapshot");
        assert_eq!(
            snap.target_system_sealed_data.as_deref(),
            Some("opaque-target-blob")
        );
        assert_eq!(
            snap.target_system_wrapped_key.as_deref(),
            Some("opaque-target-key")
        );
        assert_eq!(
            snap.rotation_config_sealed_data.as_deref(),
            Some("opaque-config-blob")
        );
        assert_eq!(
            snap.rotation_config_wrapped_key.as_deref(),
            Some("opaque-config-key")
        );
    }

    #[test]
    fn parse_work_snapshot_missing_sealed_blobs_still_parses() {
        use bitwarden_api_api::models::RotationClaimResponseModel;
        use chrono::Utc;

        let model = RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("test-system".to_owned()),
            target_system_sealed_data: None,
            target_system_wrapped_key: None,
            cipher_id: Some(Uuid::new_v4()),
            rotation_config_sealed_data: None,
            rotation_config_wrapped_key: None,
            execute_by: Some(Utc::now().to_rfc3339()),
        };

        let snap = parse_work_snapshot(model).expect("parse_work_snapshot");
        assert!(snap.target_system_sealed_data.is_none());
        assert!(snap.target_system_wrapped_key.is_none());
        assert!(snap.rotation_config_sealed_data.is_none());
        assert!(snap.rotation_config_wrapped_key.is_none());
    }

    #[test]
    fn parse_work_snapshot_missing_field_is_protocol_error() {
        use bitwarden_api_api::models::RotationClaimResponseModel;

        let model = RotationClaimResponseModel::new();
        let err = parse_work_snapshot(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    #[test]
    fn parse_work_snapshot_bad_execute_by_is_protocol_error() {
        use bitwarden_api_api::models::RotationClaimResponseModel;

        let model = RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("ts".to_owned()),
            target_system_sealed_data: Some("opaque-target-blob".to_owned()),
            target_system_wrapped_key: Some("opaque-target-key".to_owned()),
            cipher_id: Some(Uuid::new_v4()),
            rotation_config_sealed_data: Some("opaque-config-blob".to_owned()),
            rotation_config_wrapped_key: Some("opaque-config-key".to_owned()),
            execute_by: Some("NOT-A-DATE".to_owned()),
        };

        let err = parse_work_snapshot(model).expect_err("should fail");
        assert!(matches!(err, ApiError::Protocol(_)));
    }

    #[test]
    fn claim_409_maps_to_ok_none() {
        // claim() intercepts a 409 before classify_error, which on its own maps it to Rejected.
        let rc = bitwarden_api_base::ResponseContent {
            status: reqwest::StatusCode::CONFLICT,
            message: String::new(),
        };
        let err: bitwarden_api_base::Error = bitwarden_api_base::Error::Response(rc);
        let api_err = classify_error(err, Route::AccessConnectorOrJob);
        assert!(matches!(api_err, ApiError::Rejected { status: 409 }));
    }

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

    #[tokio::test]
    async fn poll_happy_path_bumps_connectivity_and_parses_jobs() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, mut connectivity_rx) = make_rotation_api(&api_server, session);

        let before = *connectivity_rx.borrow();

        let job_id = Uuid::new_v4();
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
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
            .and(path("/access-connectors/rotation/jobs"))
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
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job_id}/claim"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "attemptId": attempt_id,
                        "jobId": job_id,
                        "targetSystemId": target_system_id,
                        "targetSystemName": "my-script",
                        "targetSystemSealedData": "opaque-target-blob",
                        "targetSystemWrappedKey": "opaque-target-key",
                        "cipherId": cipher_id,
                        "rotationConfigSealedData": "opaque-config-blob",
                        "rotationConfigWrappedKey": "opaque-config-key",
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
        assert_eq!(
            snap.target_system_sealed_data.as_deref(),
            Some("opaque-target-blob")
        );
        assert_eq!(
            snap.target_system_wrapped_key.as_deref(),
            Some("opaque-target-key")
        );
        assert_eq!(
            snap.rotation_config_sealed_data.as_deref(),
            Some("opaque-config-blob")
        );
        assert_eq!(
            snap.rotation_config_wrapped_key.as_deref(),
            Some("opaque-config-key")
        );
    }

    #[tokio::test]
    async fn claim_409_maps_to_ok_none_integrated() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_rotation_api(&api_server, session);

        let job_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/jobs/{job_id}/claim"
            )))
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
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/cipher"
            )))
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
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/cipher"
            )))
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
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/cipher"
            )))
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

        Mock::given(method("POST"))
            .and(path(format!(
                "/access-connectors/rotation/attempts/{attempt_id}/failure"
            )))
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

        // 1 = TargetUpdated.
        assert_eq!(
            body["syncState"],
            serde_json::Value::Number(serde_json::Number::from(1)),
            "syncState must be an integer, got: {}",
            body["syncState"]
        );

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

        // A raw client, so requests carry no AuthRequired extension.
        let http_client = bitwarden_api_base::new_http_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let client = ClientBuilder::new(http_client)
            .with(AccessConnectorAuthMiddleware::new(handler_for(Arc::clone(
                &session,
            ))))
            .build();

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&api_server)
            .await;

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
        let org_key1 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload1 = encrypted_payload_for(&org_key1);
        let org_key2 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload2 = encrypted_payload_for(&org_key2);

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
        let session = SessionManager::new(identity_client, test_token(), KeyStore::default())
            .await
            .expect("SessionManager::new");

        let bearer_1 = format!("Bearer {}", access_token_tagged(test_org_id(), "bearer-1"));
        let bearer_2 = format!("Bearer {}", access_token_tagged(test_org_id(), "bearer-2"));

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .and(header("Authorization", bearer_1.as_str()))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&api_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .and(header("Authorization", bearer_2.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": []}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&api_server)
            .await;

        let (tx, _rx) = watch::channel(Instant::now());
        let api = RotationApi::new(api_configurations_for(&api_server, session), tx);

        let jobs = api.poll_jobs().await.expect("poll_jobs after 401-refresh");
        assert!(jobs.is_empty());

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

    /// Issue a request through the client's own API HTTP stack, the one
    /// [`build_sdk_client`] assembled.
    async fn get_through_client(
        client: &Client,
        url: String,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        client
            .internal
            .get_api_configurations()
            .api_config
            .client
            .get(url)
            .send()
            .await
    }

    /// R1: core's builder sets no per-request timeout, so a black-holed connection would
    /// otherwise hang forever and starve the heartbeat past AccessAccessConnectorOfflineAfter.
    #[tokio::test]
    async fn request_times_out_rather_than_hanging() {
        let api_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stall"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&api_server)
            .await;

        let (client, _handler) = build_sdk_client(
            api_server.uri(),
            "http://identity.invalid".to_string(),
            Duration::from_millis(100),
        );

        let started = Instant::now();
        let err = get_through_client(&client, format!("{}/stall", api_server.uri()))
            .await
            .expect_err("a stalled request must fail, not hang");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must fail on the timeout, not wait out the response"
        );
        match err {
            reqwest_middleware::Error::Middleware(e) => assert!(
                e.downcast_ref::<crate::api::RequestTimedOutError>()
                    .is_some(),
                "expected RequestTimedOutError, got {e:?}"
            ),
            other => panic!("expected a middleware error, got {other:?}"),
        }
    }

    /// R2: core disables redirects only when the extra-middleware vec is non-empty, and the
    /// auth middleware does not count toward it. Following one would let the server redirect
    /// the connector onto an arbitrary host and have its reply read as the API's.
    #[tokio::test]
    async fn does_not_follow_a_cross_host_redirect() {
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&elsewhere)
            .await;

        let api_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("{}/elsewhere", elsewhere.uri()).as_str(),
            ))
            .mount(&api_server)
            .await;

        let (client, _handler) = build_sdk_client(
            api_server.uri(),
            "http://identity.invalid".to_string(),
            Duration::from_secs(5),
        );

        let response = get_through_client(&client, format!("{}/redirect", api_server.uri()))
            .await
            .expect("the 302 itself is a successful exchange");

        assert_eq!(
            response.status(),
            302,
            "the redirect must be returned, not followed"
        );
        assert!(
            elsewhere.received_requests().await.unwrap().is_empty(),
            "the redirect target must never be contacted"
        );
    }

    /// A credential rejected on the 401-refresh path must surface as a typed `Revoked`.
    #[tokio::test]
    async fn revoked_session_classifies_as_session_lost_revoked() {
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = encrypted_payload_for(&org_key);

        // Startup authentication succeeds; the forced refresh after the 401 is rejected.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response("bearer-1", 3600, &payload))
            .up_to_n_times(1)
            .mount(&identity_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"invalid_grant"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&identity_server)
            .await;

        let identity_client = IdentityClient::new(identity_server.uri()).expect("identity client");
        let session = SessionManager::new(identity_client, test_token(), KeyStore::default())
            .await
            .expect("startup auth succeeds");

        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&api_server)
            .await;

        let (api, _rx) = make_rotation_api(&api_server, Arc::clone(&session));

        let err = api.poll_jobs().await.expect_err("credential was rejected");
        assert!(
            matches!(err, ApiError::SessionLost(SessionLost::Revoked)),
            "expected SessionLost(Revoked), got {err:?}"
        );
        assert_eq!(
            session.phase().await,
            crate::auth::session::SessionPhase::Revoked
        );
    }

    /// Shutdown must carry `Closed`, which the executor treats differently from `Revoked`.
    #[tokio::test]
    async fn closed_session_classifies_as_session_lost_closed() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "bearer-1").await;
        let (api, _rx) = make_rotation_api(&api_server, Arc::clone(&session));

        session.close().await;

        let err = api.poll_jobs().await.expect_err("session was closed");
        assert!(
            matches!(err, ApiError::SessionLost(SessionLost::Closed)),
            "expected SessionLost(Closed), got {err:?}"
        );

        assert!(
            api_server.received_requests().await.unwrap().is_empty(),
            "no API request should be issued after the session is closed"
        );
    }

    /// A middleware adding context must not bury the signal: `Revoked` degrading to
    /// `Transient` would make the executor retry instead of exiting `CredentialRefused`.
    #[test]
    fn session_loss_survives_a_wrapped_error() {
        let wrapped = reqwest_middleware::Error::Middleware(
            anyhow::Error::new(SessionError::Lost(SessionLost::Revoked))
                .context("daemon API request failed"),
        );

        assert_eq!(session_loss(&wrapped), Some(SessionLost::Revoked));
    }

    /// Another middleware's error must not be mistaken for session loss, however it reads.
    #[test]
    fn foreign_middleware_error_is_not_session_loss() {
        let impostor =
            reqwest_middleware::Error::Middleware(anyhow::anyhow!("session lost: Revoked"));

        assert!(
            session_loss(&impostor).is_none(),
            "only a downcastable SessionError counts as session loss"
        );
    }
}
