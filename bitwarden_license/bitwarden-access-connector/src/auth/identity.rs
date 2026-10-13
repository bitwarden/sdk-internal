//! OAuth2 client-credentials grant against `{identity_url}/connect/token`, requesting
//! `scope=api.pam.rotation`.

use std::time::Duration;

use bitwarden_access_token::AccessToken;
use bitwarden_api_base::new_http_client_builder;
use bitwarden_sensitive_value::SensitiveString;
use serde::Deserialize;
use thiserror::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const SCOPE: &str = "api.pam.rotation";

/// A successful authentication response from the identity server. `Debug` is hand-written to
/// redact `access_token`.
pub(crate) struct AuthSuccess {
    pub(crate) access_token: SensitiveString,
    /// Token lifetime in seconds.
    pub(crate) expires_in: u64,
    /// The organisation key wrapped under the connector's encryption key (EncString).
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
    /// The identity server rejected the credential (`invalid_client`, `invalid_grant`,
    /// `unauthorized_client`). Terminal: do not retry with the same credential.
    #[error("credential rejected by identity server")]
    Rejected,

    /// A connection failure, 429, 5xx or other unexpected status; retryable after a delay.
    #[error("transient error contacting identity server: {0}")]
    Transient(String),

    /// The response was not the expected JSON, or carried an unrecognised OAuth error.
    #[error("identity server returned an unexpected response")]
    Protocol,
}

/// HTTP client for the `POST /connect/token` identity endpoint.
pub(crate) struct IdentityClient {
    http: reqwest::Client,
    identity_url: String,
}

impl IdentityClient {
    /// Uses [`new_http_client_builder`] because the workspace `reqwest` has no TLS backend of its
    /// own.
    pub(crate) fn new(identity_url: String) -> Result<Self, reqwest::Error> {
        let http = new_http_client_builder()
            .timeout(REQUEST_TIMEOUT)
            // Never follow redirects: a redirected credential post would send the client_secret to
            // an unexpected endpoint.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { http, identity_url })
    }

    /// POST `{identity_url}/connect/token` with a `client_credentials` grant. Neither the form body
    /// nor the raw response body is ever logged.
    pub(crate) async fn authenticate(&self, token: &AccessToken) -> Result<AuthSuccess, AuthError> {
        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));

        // Copied out only to build the form; the secret never enters a log or error message.
        use bitwarden_sensitive_value::ExposeSensitive as _;
        let secret_value = token.client_secret().expose().to_owned();
        let client_id = token.client_id();

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
            // The OAuth `error` field separates Rejected from Protocol. The raw body is never
            // logged.
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

        // The success body carries the bearer token; never log it.
        let body_bytes = response.bytes().await.map_err(|_| AuthError::Protocol)?;

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
            // The identity server emits this field as snake_case `encrypted_payload`.
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

#[cfg(test)]
mod tests {
    use bitwarden_access_token::AccessTokenKind;
    use bitwarden_sensitive_value::ExposeSensitive as _;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    use super::{AccessToken, AuthError, IdentityClient};

    const VALID_TOKEN_STR: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn test_token() -> AccessToken {
        AccessToken::parse(VALID_TOKEN_STR, AccessTokenKind::AccessConnector).expect("valid token")
    }

    fn client(server: &MockServer) -> IdentityClient {
        IdentityClient::new(server.uri()).expect("client build")
    }

    fn success_body(access_token: &str, expires_in: u64) -> String {
        format!(
            r#"{{"access_token":"{access_token}","expires_in":{expires_in},"encrypted_payload":"2.abc==|def==|ghi=="}}"#
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
            .and(body_string_contains("client_id=access-connector."))
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

    /// The identity server emits snake_case `encrypted_payload`; a camelCase field alone must not
    /// parse.
    #[tokio::test]
    async fn camel_case_encrypted_payload_gives_protocol() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"access_token":"tok","expires_in":3600,"encryptedPayload":"2.abc==|def==|ghi=="}"#,
                    )
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
            "expected Protocol for camelCase field, got {err:?}"
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
