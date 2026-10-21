//! HTTP API client wrappers for the Bitwarden server's PAM rotation endpoints.
//!
//! [`build_sdk_client`] assembles the client the connector runs on; [`AccessConnectorClient`]
//! reaches through its configurations, mapping calls into domain types.

pub(crate) mod models;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_api_api::{
    apis::AuthRequired,
    models::{ReportRotationFailedRequestModel, ReportRotationSucceededRequestModel},
};
use bitwarden_core::{
    Client, ClientBuilder, ClientSettings, FromClient, client::internal::ApiConfigurations,
    key_management::KeySlotIds,
};
use bitwarden_crypto::KeyStore;
use bitwarden_pam::{
    RotationFailureCode, RotationSyncState, SessionTerminationOutcome, WorkSnapshot,
};
use models::{ApiError, JobRef};
use reqwest_middleware::{Middleware, Next};
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    auth::{
        session::{SessionError, SessionManager},
        token_handler::AccessConnectorTokenHandler,
    },
    error::SafeDetail,
};

/// [`reqwest_middleware::Middleware`] that attaches the connector bearer token and retries one 401
/// after a forced refresh. Unlike bitwarden-auth's middleware, it fails on session loss instead of
/// sending the request without a token.
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
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::new(e)))
    }

    async fn force_refresh_bearer(&self, stale: &str) -> Result<String, reqwest_middleware::Error> {
        self.session()?
            .force_refresh(stale, None)
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::new(e)))
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

/// Keeps a black-holed connection from starving the heartbeat past `AccessConnectorOfflineAfter`.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Applies [`REQUEST_TIMEOUT`] to a whole request; core sets none.
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

/// Records the last successful server contact, which the rotation gate reads to pause target-side
/// steps while the server is unreachable.
///
/// Any 2xx status counts, even if the body later fails to parse: the server answered. Redirects,
/// client errors and server errors, and transport failures, do not.
pub(crate) struct ConnectivityMiddleware {
    last_ok_tx: watch::Sender<Instant>,
}

impl ConnectivityMiddleware {
    pub(crate) fn new(last_ok_tx: watch::Sender<Instant>) -> Self {
        Self { last_ok_tx }
    }
}

#[async_trait::async_trait]
impl Middleware for ConnectivityMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let response = next.run(req, ext).await?;
        if response.status().is_success() {
            self.last_ok_tx.send_modify(|t| *t = Instant::now());
        }
        Ok(response)
    }
}

/// Builds the SDK client the connector runs against, plus the handler that carries its session
/// once startup has one.
///
/// [`TimeoutMiddleware`] is load-bearing twice: core sets no per-request timeout, and it disables
/// redirect-following only when the extra-middleware vec is non-empty (the auth middleware does not
/// count). `request_times_out_rather_than_hanging` and `does_not_follow_a_cross_host_redirect`
/// guard both.
///
/// Redirects are refused because these endpoints never legitimately redirect, not because the
/// bearer would leak (reqwest strips `Authorization` on a host change): following one would read
/// another host's reply as the API's and, on a 307, forward the encrypted cipher body.
///
/// Chained outermost, the timeout also bounds token renewal. [`ConnectivityMiddleware`] sits
/// outside the auth middleware, so a 401 retried into a 2xx counts once and a persistent 401 not.
pub(crate) fn build_sdk_client(
    api_url: String,
    identity_url: String,
    timeout: Duration,
    last_ok_tx: watch::Sender<Instant>,
) -> (Client, AccessConnectorTokenHandler) {
    let handler = AccessConnectorTokenHandler::default();

    let client = ClientBuilder::new()
        .with_settings(ClientSettings {
            api_url,
            identity_url,
            ..Default::default()
        })
        .with_token_handler(Arc::new(handler.clone()))
        .with_middleware(vec![
            Arc::new(TimeoutMiddleware::new(timeout)),
            Arc::new(ConnectivityMiddleware::new(last_ok_tx)),
        ])
        .build();

    (client, handler)
}

/// Domain-typed wrapper around the generated PAM rotation API clients.
#[derive(FromClient)]
pub(crate) struct AccessConnectorClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

/// Extension trait that exposes [`AccessConnectorClient`] on [`Client`].
pub(crate) trait AccessConnectorClientExt {
    fn access_connector(&self) -> AccessConnectorClient;
}

impl AccessConnectorClientExt for Client {
    fn access_connector(&self) -> AccessConnectorClient {
        AccessConnectorClient::from_client(self)
    }
}

impl AccessConnectorClient {
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
                let snapshot =
                    WorkSnapshot::try_from(model).map_err(|e| ApiError::Protocol(e.to_string()))?;
                Ok(Some(snapshot))
            }
            Err(bitwarden_api_base::Error::Response(ref rc)) if rc.status.as_u16() == 409 => {
                Ok(None)
            }
            Err(e) => Err(classify_error(e, Route::AccessConnectorOrJob)),
        }
    }

    /// Report a successful rotation attempt. A 409 or 404 is final: do not retry.
    pub(crate) async fn report_success(
        &self,
        attempt_id: Uuid,
        termination: SessionTerminationOutcome,
    ) -> Result<(), ApiError> {
        let body = ReportRotationSucceededRequestModel {
            session_termination: termination.try_into().map_err(unrecognized_variant)?,
        };

        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .success(attempt_id, body)
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }

    /// Report a failed rotation attempt. A 409 or 404 is final, as in [`Self::report_success`].
    pub(crate) async fn report_failure(
        &self,
        attempt_id: Uuid,
        code: RotationFailureCode,
        detail: Option<SafeDetail>,
        sync_state: RotationSyncState,
    ) -> Result<(), ApiError> {
        let body = ReportRotationFailedRequestModel {
            sync_state: sync_state.try_into().map_err(unrecognized_variant)?,
            error_code: code.as_token().map_err(unrecognized_variant)?.to_owned(),
            detail: detail.map(|d| d.as_str().to_owned()),
        };

        let result = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_attempts_api()
            .failure(attempt_id, body)
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(classify_error(e, Route::Attempt)),
        }
    }
}

/// Route class, for disambiguating 404 semantics.
#[derive(Clone, Copy)]
enum Route {
    /// `jobs` and `jobs/{id}/claim`: a 404 means the connector is not eligible.
    AccessConnectorOrJob,
    /// `attempts/{id}/…`: a 404 means the server does not know the attempt.
    Attempt,
}

fn classify_error(err: bitwarden_api_base::Error, route: Route) -> ApiError {
    use bitwarden_api_base::Error;

    match err {
        Error::Response(rc) => {
            let status = rc.status.as_u16();
            match status {
                401 => {
                    // No async context to read session.phase(), so a post-retry 401 maps to
                    // Transient; terminal loss surfaces earlier.
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
        Error::ReqwestMiddleware(mw_err) => {
            // The SessionError stays typed inside the middleware error, so loss is detected by
            // type.
            if let reqwest_middleware::Error::Middleware(inner) = &mw_err
                && let Some(SessionError::Lost(l)) = inner.downcast_ref::<SessionError>()
            {
                ApiError::SessionLost(*l)
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
    }
}

/// Names only the variant of a [`reqwest_middleware::Error`]; its message can wrap arbitrary
/// strings.
fn safe_middleware_description(err: &reqwest_middleware::Error) -> &'static str {
    match err {
        reqwest_middleware::Error::Middleware(_) => "middleware error",
        reqwest_middleware::Error::Reqwest(_) => "reqwest error",
    }
}

/// The connector never constructs an `Unknown` variant, so this guard failure is a bug rather than
/// a server response.
fn unrecognized_variant(_: bitwarden_pam::RotationError) -> ApiError {
    ApiError::Protocol("unrecognized variant".to_owned())
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
        auth::{
            identity::IdentityClient,
            session::{SessionLost, SessionManager},
        },
        error::SafeDetail,
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

    /// Like [`make_session`], but only the first token request succeeds; later requests fall
    /// through to whatever the test mounts next.
    async fn make_session_once(identity_server: &MockServer, bearer: &str) -> Arc<SessionManager> {
        let org_key = bitwarden_crypto::SymmetricCryptoKey::make(
            bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac,
        );
        let payload = encrypted_payload_for(&org_key);

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(identity_success_response(bearer, 3600, &payload))
            .up_to_n_times(1)
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

    /// An [`AccessConnectorClient`] over the production client stack with `session` installed, plus
    /// the connectivity receiver.
    fn make_access_connector_client(
        api_server: &MockServer,
        session: Arc<SessionManager>,
    ) -> (AccessConnectorClient, watch::Receiver<Instant>) {
        let (tx, rx) = watch::channel(Instant::now());
        let (client, handler) = build_sdk_client(
            api_server.uri(),
            "http://identity.invalid".to_owned(),
            REQUEST_TIMEOUT,
            tx,
        );
        handler.set_session(session);
        (client.access_connector(), rx)
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

    #[tokio::test]
    async fn poll_happy_path_bumps_connectivity_and_parses_jobs() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, mut connectivity_rx) = make_access_connector_client(&api_server, session);

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
        let (api, _rx) = make_access_connector_client(&api_server, session);

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
        let (api, _rx) = make_access_connector_client(&api_server, session);

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
        let (api, _rx) = make_access_connector_client(&api_server, session);

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
    async fn failure_report_serialises_integer_sync_state_and_snake_case_error_code() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;

        let session = make_session(&identity_server, "test-bearer").await;
        let (api, _rx) = make_access_connector_client(&api_server, session);

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
            RotationFailureCode::TargetUnreachable,
            Some(SafeDetail::from_status(503)),
            RotationSyncState::TargetUpdated,
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

        let (api, _rx) = make_access_connector_client(&api_server, session);

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

    /// Mounts a 401 on the jobs endpoint so every call forces a refresh.
    async fn mount_jobs_401(api_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/access-connectors/rotation/jobs"))
            .respond_with(ResponseTemplate::new(401))
            .mount(api_server)
            .await;
    }

    /// Issue a request through the HTTP stack [`build_sdk_client`] assembled.
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

    /// Sends a GET to `url` through a fresh client and reports whether connectivity was bumped.
    async fn bumps_connectivity(url: String) -> bool {
        let (tx, mut rx) = watch::channel(Instant::now());
        let (client, _handler) = build_sdk_client(
            "http://api.invalid".to_owned(),
            "http://identity.invalid".to_owned(),
            Duration::from_secs(5),
            tx,
        );
        let before = *rx.borrow_and_update();

        let _ = get_through_client(&client, url).await;

        rx.has_changed().expect("sender alive") && *rx.borrow() > before
    }

    #[tokio::test]
    async fn connectivity_is_bumped_by_a_2xx_even_with_an_unparseable_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        assert!(bumps_connectivity(format!("{}/ok", server.uri())).await);
    }

    #[tokio::test]
    async fn connectivity_is_not_bumped_by_non_2xx_responses() {
        let server = MockServer::start().await;
        for status in [302, 401, 404, 409, 500, 503] {
            Mock::given(method("GET"))
                .and(path(format!("/status/{status}")))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            assert!(
                !bumps_connectivity(format!("{}/status/{status}", server.uri())).await,
                "{status} must not count as server contact"
            );
        }
    }

    #[tokio::test]
    async fn connectivity_is_not_bumped_by_a_transport_error() {
        // Nothing listens on port 1.
        assert!(!bumps_connectivity("http://127.0.0.1:1/x".to_owned()).await);
    }

    #[tokio::test]
    async fn connectivity_is_not_bumped_by_a_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stall"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let (tx, rx) = watch::channel(Instant::now());
        let (client, _handler) = build_sdk_client(
            server.uri(),
            "http://identity.invalid".to_owned(),
            Duration::from_millis(100),
            tx,
        );
        let before = *rx.borrow();

        get_through_client(&client, format!("{}/stall", server.uri()))
            .await
            .expect_err("times out");

        assert_eq!(*rx.borrow(), before);
    }

    #[tokio::test]
    async fn the_client_exposes_access_connector_sharing_its_key_store() {
        use bitwarden_core::key_management::SymmetricKeySlotId;
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let (tx, _rx) = watch::channel(Instant::now());
        let (client, handler) = build_sdk_client(
            "http://api.invalid".to_owned(),
            "http://identity.invalid".to_owned(),
            REQUEST_TIMEOUT,
            tx,
        );

        let org_id = crate::test_support::test_org_id();
        let slot = SymmetricKeySlotId::Organization(org_id);

        let access_connector = client.access_connector();
        assert!(!access_connector.key_store.context().has_symmetric_key(slot));

        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = handler.key_store().expect("key store");
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(slot, org_key)
            .expect("set key");

        // The key reached a client handed out earlier and one handed out later.
        for c in [access_connector, client.access_connector()] {
            assert!(c.key_store.context().has_symmetric_key(slot));
        }
    }

    /// R1: a black-holed connection must time out.
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
            watch::channel(Instant::now()).0,
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

    /// R2: a cross-host redirect must not be followed.
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
            watch::channel(Instant::now()).0,
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

    #[tokio::test]
    async fn forced_refresh_rejected_maps_to_session_lost_revoked() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        let session = make_session_once(&identity_server, "bearer-1").await;
        // The first token request succeeded; the forced refresh is rejected.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"invalid_client"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&identity_server)
            .await;
        mount_jobs_401(&api_server).await;

        let (api, _rx) = make_access_connector_client(&api_server, session);

        let err = api.poll_jobs().await.expect_err("revoked mid-session");
        assert!(
            matches!(err, ApiError::SessionLost(SessionLost::Revoked)),
            "expected SessionLost(Revoked), got {err:?}"
        );
    }

    #[tokio::test]
    async fn call_after_session_close_maps_to_session_lost_closed() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        let session = make_session(&identity_server, "bearer-1").await;
        session.close().await;

        let (api, _rx) = make_access_connector_client(&api_server, session);

        let err = api.poll_jobs().await.expect_err("session closed");
        assert!(
            matches!(err, ApiError::SessionLost(SessionLost::Closed)),
            "expected SessionLost(Closed), got {err:?}"
        );
        assert!(
            api_server.received_requests().await.unwrap().is_empty(),
            "no request should reach the API once the session is closed"
        );
    }

    // Runs in real time (~3 s of session backoff): paused time breaks the HTTP client's connect
    // timeout.
    #[tokio::test]
    async fn forced_refresh_transient_failure_maps_to_transient() {
        let identity_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        let session = make_session_once(&identity_server, "bearer-1").await;
        // The first token request succeeded; the forced refresh keeps failing with a 5xx.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&identity_server)
            .await;
        mount_jobs_401(&api_server).await;

        let (api, _rx) = make_access_connector_client(&api_server, session);

        let err = api.poll_jobs().await.expect_err("refresh keeps failing");
        assert!(
            matches!(err, ApiError::Transient(_)),
            "expected Transient, got {err:?}"
        );
    }
}
