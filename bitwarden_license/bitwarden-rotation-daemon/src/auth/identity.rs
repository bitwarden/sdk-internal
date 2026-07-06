//! Identity server interaction for obtaining access tokens.
//!
//! Implements the OAuth2 client-credentials grant against
//! `{identity_url}/connect/token` — the same endpoint the SM daemon uses,
//! but with `scope=api.pam.rotation` and a 4-part daemon token format.

use std::time::Duration;

use bitwarden_api_base::new_http_client_builder;
use bitwarden_sensitive_value::SensitiveString;
use serde::Deserialize;
use thiserror::Error;

use crate::token::DaemonToken;

/// How long to wait for the identity server before giving up on a single request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The OAuth2 scope requested from the identity server.
const SCOPE: &str = "api.pam.rotation";

/// A successful authentication response from the identity server.
///
/// `Debug` is implemented manually to redact `access_token`.
pub(crate) struct AuthSuccess {
    /// The short-lived bearer access token.  Redacted in `Debug`.
    pub(crate) access_token: SensitiveString,
    /// Token lifetime in seconds as reported by the server.
    pub(crate) expires_in: u64,
    /// The organisation key wrapped under the daemon's encryption key (EncString).
    pub(crate) encrypted_payload: String,
}

impl std::fmt::Debug for AuthSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSuccess")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// Errors returned by [`IdentityClient::authenticate`].
#[derive(Debug, Error)]
pub(crate) enum AuthError {
    /// The identity server explicitly rejected the credential (e.g. `invalid_client`,
    /// `invalid_grant`, `unauthorized_client`).  This is a terminal condition — the
    /// daemon must not retry with the same credential.
    #[error("credential rejected by identity server")]
    Rejected,

    /// A transient network or server error (5xx, 429, connection failure).  The caller
    /// may retry after a delay.
    #[error("transient error contacting identity server: {0}")]
    Transient(String),

    /// The server returned a response that could not be parsed as the expected JSON.
    /// Indicates a server-side contract violation.
    #[error("identity server returned an unexpected response")]
    Protocol,
}

/// HTTP client for the `POST /connect/token` identity endpoint.
pub(crate) struct IdentityClient {
    http: reqwest::Client,
    identity_url: String,
}

impl IdentityClient {
    /// Build a new client targeting `identity_url`.
    ///
    /// Uses [`new_http_client_builder`] (rustls + platform verifier + `https_only`
    /// in release) — the workspace `reqwest` has no TLS backend built in.
    pub(crate) fn new(identity_url: String) -> Result<Self, reqwest::Error> {
        let http = new_http_client_builder()
            .timeout(REQUEST_TIMEOUT)
            // Disable automatic redirect following: the identity server never
            // legitimately redirects credential posts; following a redirect would
            // send the client_secret to an unexpected endpoint.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { http, identity_url })
    }

    /// POST `{identity_url}/connect/token` with a `client_credentials` grant.
    ///
    /// On success returns the bearer token, expiry, and the wrapped org-key payload.
    /// The request form body and raw response body are never logged.
    pub(crate) async fn authenticate(&self, token: &DaemonToken) -> Result<AuthSuccess, AuthError> {
        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));

        // We must expose the client_secret value to place it in the form.
        // It is a short-lived local borrow; it never enters any log or error message.
        use bitwarden_sensitive_value::ExposeSensitive as _;
        let secret_value = token.client_secret.expose().to_owned();
        let client_id = token.client_id();

        // Build the form as a vec so all fields — including the sensitive secret —
        // are assembled in one place and discarded immediately after the send call.
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &secret_value),
            ("scope", SCOPE),
        ];

        let response = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| AuthError::Transient(e.to_string()))?;

        let status = response.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(AuthError::Transient(format!("HTTP {}", status.as_u16())));
        }

        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            // Parse the OAuth error field to distinguish rejected vs. protocol.
            // We do NOT log the raw body.
            let body_bytes = response.bytes().await.map_err(|_| AuthError::Protocol)?;

            #[derive(Deserialize)]
            struct OAuthError {
                error: Option<String>,
            }

            let parsed: OAuthError =
                serde_json::from_slice(&body_bytes).map_err(|_| AuthError::Protocol)?;

            match parsed.error.as_deref() {
                Some("invalid_client" | "invalid_grant" | "unauthorized_client") => {
                    return Err(AuthError::Rejected);
                }
                _ => return Err(AuthError::Protocol),
            }
        }

        if !status.is_success() {
            return Err(AuthError::Transient(format!("HTTP {}", status.as_u16())));
        }

        // Parse the success body.  We do NOT log it.
        let body_bytes = response.bytes().await.map_err(|_| AuthError::Protocol)?;

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
            #[serde(rename = "encryptedPayload")]
            encrypted_payload: String,
        }

        let parsed: TokenResponse =
            serde_json::from_slice(&body_bytes).map_err(|_| AuthError::Protocol)?;

        Ok(AuthSuccess {
            access_token: SensitiveString::from(parsed.access_token),
            expires_in: parsed.expires_in,
            encrypted_payload: parsed.encrypted_payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_sensitive_value::ExposeSensitive as _;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{AuthError, IdentityClient};
    use crate::token::DaemonToken;

    const VALID_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn test_token() -> DaemonToken {
        DaemonToken::from_str(VALID_TOKEN_STR).expect("valid token")
    }

    fn client(server: &MockServer) -> IdentityClient {
        IdentityClient::new(server.uri()).expect("client build")
    }

    fn success_body(access_token: &str, expires_in: u64) -> String {
        format!(
            r#"{{"access_token":"{access_token}","expires_in":{expires_in},"encryptedPayload":"2.abc==|def==|ghi=="}}"#
        )
    }

    #[tokio::test]
    async fn successful_auth_returns_token_and_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(success_body("test-bearer", 3600))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let result = client(&server)
            .authenticate(&test_token())
            .await
            .expect("authenticate");

        assert_eq!(result.access_token.expose(), "test-bearer");
        assert_eq!(result.expires_in, 3600);
        assert_eq!(result.encrypted_payload, "2.abc==|def==|ghi==");
    }

    #[tokio::test]
    async fn sends_correct_form_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("scope=api.pam.rotation"))
            .and(body_string_contains("client_id=daemon."))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(success_body("tok", 3600))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        client(&server)
            .authenticate(&test_token())
            .await
            .expect("authenticate");

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_client_gives_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"invalid_client"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(
            matches!(err, AuthError::Rejected),
            "expected Rejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_grant_gives_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string(r#"{"error":"invalid_grant"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(matches!(err, AuthError::Rejected));
    }

    #[tokio::test]
    async fn unauthorized_client_gives_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string(r#"{"error":"unauthorized_client"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(matches!(err, AuthError::Rejected));
    }

    #[tokio::test]
    async fn server_error_gives_transient() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(
            matches!(err, AuthError::Transient(_)),
            "expected Transient, got {err:?}"
        );
    }

    #[tokio::test]
    async fn too_many_requests_gives_transient() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(matches!(err, AuthError::Transient(_)));
    }

    #[tokio::test]
    async fn malformed_success_body_gives_protocol() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("not json at all")
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(
            matches!(err, AuthError::Protocol),
            "expected Protocol, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unknown_oauth_error_gives_protocol() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"some_other_error"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        assert!(
            matches!(err, AuthError::Protocol),
            "expected Protocol, got {err:?}"
        );
    }

    #[tokio::test]
    async fn secret_not_visible_in_error_messages() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = client(&server)
            .authenticate(&test_token())
            .await
            .expect_err("should fail");

        let err_str = format!("{err:?}");
        assert!(
            !err_str.contains("C2IgxjjLF7qSshsbwe8JGcbM075YXw"),
            "error message must not contain client secret: {err_str}"
        );
    }
}
