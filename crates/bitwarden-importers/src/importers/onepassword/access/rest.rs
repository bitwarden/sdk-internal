//! reqwest wrapper: identity headers, the MAC signing hook, encrypted GET/POST, and error parsing.

use rand::Rng;
use reqwest::{
    Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    error::OnePasswordError,
    mac::MacSigner,
    opdata::{AesKey, Encrypted},
    wire::{EncryptedEnvelope, ErrorResponse, FailureReason},
};

const CLIENT_HEADER: &str = "x-agilebits-client";
const USER_AGENT_HEADER: &str = "user-agent";
const OP_USER_AGENT_HEADER: &str = "op-user-agent";
const SESSION_ID_HEADER: &str = "x-agilebits-session-id";
const MAC_HEADER: &str = "x-agilebits-mac";
const IV_SIZE: usize = 12;

/// An HTTP client bound to a base URL, carrying the 1Password identity headers and an optional MAC
/// signer. Requests are signed automatically once a signer is attached.
pub(super) struct RestClient {
    http: reqwest::Client,
    base_url: String,
    headers: HeaderMap,
    signer: Option<MacSigner>,
}

impl RestClient {
    /// Builds the base client with the identity headers derived from `ClientInfo`.
    pub(super) fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        client_id: &str,
        user_agent: &str,
        op_user_agent: &str,
    ) -> Result<RestClient, OnePasswordError> {
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, CLIENT_HEADER, client_id)?;
        insert_header(&mut headers, USER_AGENT_HEADER, user_agent)?;
        insert_header(&mut headers, OP_USER_AGENT_HEADER, op_user_agent)?;

        Ok(RestClient {
            http,
            base_url: base_url.into(),
            headers,
            signer: None,
        })
    }

    /// Derives a client that adds the session id header.
    pub(super) fn with_session_id(&self, session_id: &str) -> Result<RestClient, OnePasswordError> {
        let mut headers = self.headers.clone();
        insert_header(&mut headers, SESSION_ID_HEADER, session_id)?;

        Ok(RestClient {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            headers,
            signer: None,
        })
    }

    /// Derives a client that signs every request. The signer carries the session id already, so
    /// this keeps whatever headers the receiver has.
    pub(super) fn with_signer(&self, signer: MacSigner) -> RestClient {
        RestClient {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            headers: self.headers.clone(),
            signer: Some(signer),
        }
    }

    /// POSTs a JSON body and parses the JSON response.
    pub(super) async fn post_json<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: Value,
    ) -> Result<T, OnePasswordError> {
        self.request_json(Method::POST, endpoint, Some(&body)).await
    }

    /// PUTs with no body and parses the JSON response.
    pub(super) async fn put<T: DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> Result<T, OnePasswordError> {
        self.request_json(Method::PUT, endpoint, None).await
    }

    /// GETs an opdata envelope, decrypts it, and parses the JSON plaintext.
    pub(super) async fn get_encrypted_json<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        session_key: &AesKey,
    ) -> Result<T, OnePasswordError> {
        let envelope = self.request_json(Method::GET, endpoint, None).await?;
        decrypt_response(envelope, session_key)
    }

    /// Encrypts `params`, POSTs the opdata envelope, then decrypts and parses the response.
    pub(super) async fn post_encrypted_json<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        params: Value,
        session_key: &AesKey,
    ) -> Result<T, OnePasswordError> {
        let payload = serde_json::to_vec(&params)
            .map_err(|_| OnePasswordError::Internal("failed to serialize request".into()))?;

        let mut iv = [0u8; IV_SIZE];
        bitwarden_random::rng().fill_bytes(&mut iv);
        let envelope = session_key.encrypt(&payload, &iv)?;
        let body = serde_json::to_value(&envelope)
            .map_err(|_| OnePasswordError::Internal("failed to serialize envelope".into()))?;

        let response = self
            .request_json(Method::POST, endpoint, Some(&body))
            .await?;
        decrypt_response(response, session_key)
    }

    /// Sends a request and parses the JSON response.
    async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&Value>,
    ) -> Result<T, OnePasswordError> {
        let text = self.request(method, endpoint, body).await?;
        deserialize(text.as_bytes())
    }

    async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&Value>,
    ) -> Result<String, OnePasswordError> {
        let url = format!("{}/{}", self.base_url, endpoint);

        let mut builder = self
            .http
            .request(method.clone(), &url)
            .headers(self.headers.clone());
        if let Some(body) = body {
            builder = builder.json(body);
        }
        if let Some(signer) = &self.signer {
            builder = builder.header(MAC_HEADER, signer.sign(&url, method.as_str())?);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| OnePasswordError::Network(e.to_string()))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| OnePasswordError::Network(e.to_string()))?;

        if !status.is_success() {
            return Err(parse_server_error(text.as_bytes()).unwrap_or_else(|| {
                OnePasswordError::Internal(format!(
                    "unexpected response from the server (HTTP {})",
                    status.as_u16()
                ))
            }));
        }

        Ok(text)
    }
}

/// Decrypts an opdata envelope and parses its JSON plaintext.
fn decrypt_response<T: DeserializeOwned>(
    envelope: EncryptedEnvelope,
    session_key: &AesKey,
) -> Result<T, OnePasswordError> {
    let plaintext = session_key.decrypt(&Encrypted::parse(&envelope)?)?;

    // A decrypted payload can still be a server error: some errors come back HTTP 200 with the
    // error object encrypted.
    if let Some(error) = parse_server_error(&plaintext) {
        return Err(error);
    }
    deserialize(&plaintext)
}

/// Maps a 1Password error body to an `OnePasswordError`, or `None` when the body is not an error.
fn parse_server_error(body: &[u8]) -> Option<OnePasswordError> {
    if let Ok(error) = serde_json::from_slice::<ErrorResponse>(body) {
        return Some(match error.code {
            102 => OnePasswordError::BadCredentials,
            117 => OnePasswordError::NotFound,
            code => OnePasswordError::Internal(format!(
                "the server responded with error code {code}: '{}'",
                error.message
            )),
        });
    }

    if let Ok(failure) = serde_json::from_slice::<FailureReason>(body)
        && !failure.reason.is_empty()
    {
        return Some(OnePasswordError::Internal(format!(
            "the server responded with failure reason: '{}'",
            failure.reason
        )));
    }

    None
}

fn deserialize<T: DeserializeOwned>(body: &[u8]) -> Result<T, OnePasswordError> {
    serde_json::from_slice(body).map_err(|_| OnePasswordError::Parse)
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), OnePasswordError> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| OnePasswordError::Internal(format!("invalid header value for '{name}'")))?;
    headers.insert(HeaderName::from_static(name), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use serde::Deserialize;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{super::opdata::decode64_loose, *};

    #[derive(Debug, Deserialize)]
    struct Greeting {
        hello: String,
    }

    fn client(server: &MockServer) -> RestClient {
        RestClient::new(
            new_http_client(),
            format!("http://{}/api", server.address()),
            "1Password for Mac/81210036",
            "1Password for Mac/81210036",
            "op-user-agent",
        )
        .expect("valid headers")
    }

    fn session_key() -> AesKey {
        AesKey::new(
            "SESSION",
            decode64_loose("WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM").expect("valid key"),
        )
    }

    #[test]
    fn parses_error_bodies() {
        let error = parse_server_error(br#"{"errorCode":102,"errorMessage":"nope"}"#)
            .expect("recognized error");
        assert!(matches!(error, OnePasswordError::BadCredentials));

        let error = parse_server_error(br#"{"errorCode":117,"errorMessage":"gone"}"#)
            .expect("recognized error");
        assert!(matches!(error, OnePasswordError::NotFound));

        let error = parse_server_error(br#"{"errorCode":401,"errorMessage":"no auth"}"#)
            .expect("recognized error");
        assert!(matches!(error, OnePasswordError::Internal(_)));
        assert!(error.to_string().contains("401"));

        let error = parse_server_error(br#"{"reason":"rate limited"}"#).expect("recognized error");
        assert!(error.to_string().contains("rate limited"));
    }

    #[test]
    fn ignores_non_error_bodies() {
        assert!(parse_server_error(br#"{"status":"ok","sessionID":"S"}"#).is_none());
        assert!(parse_server_error(br#"{"mfa":null}"#).is_none());
    }

    #[tokio::test]
    async fn post_json_sends_identity_headers() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v2/auth/methods"))
                    .and(matchers::method("POST"))
                    .and(matchers::header(
                        "x-agilebits-client",
                        "1Password for Mac/81210036",
                    ))
                    .and(matchers::body_json(json!({"email": "user@example.com"})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hello": "you"})))
                    .expect(1),
            )
            .await;

        let response: Greeting = client(&server)
            .post_json("v2/auth/methods", json!({"email": "user@example.com"}))
            .await
            .expect("request succeeds");

        assert_eq!(response.hello, "you");
        server.verify().await;
    }

    #[tokio::test]
    async fn maps_error_responses_to_errors() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v2/auth"))
                    .respond_with(ResponseTemplate::new(401).set_body_json(
                        json!({"errorCode": 102, "errorMessage": "bad credentials"}),
                    ))
                    .expect(1),
            )
            .await;

        let error = client(&server)
            .post_json::<Greeting>("v2/auth", json!({}))
            .await
            .expect_err("server rejects");

        assert!(matches!(error, OnePasswordError::BadCredentials));
        server.verify().await;
    }

    #[tokio::test]
    async fn signs_requests_once_a_signer_is_attached() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/auth/verify"))
                    .and(matchers::header("x-agilebits-session-id", "SESSION"))
                    .and(matchers::header_regex("x-agilebits-mac", r"^v1\|\d+\|.+$"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hello": "you"})))
                    .expect(1),
            )
            .await;

        let key = session_key();
        let rest = client(&server)
            .with_session_id(&key.id)
            .expect("valid session id")
            .with_signer(MacSigner::new(&key));
        let _: Greeting = rest
            .post_json("v1/auth/verify", json!({}))
            .await
            .expect("request succeeds");

        server.verify().await;
    }

    #[tokio::test]
    async fn round_trips_an_encrypted_request() {
        let key = session_key();
        let response_body = {
            let mut iv = [0u8; IV_SIZE];
            bitwarden_random::rng().fill_bytes(&mut iv);
            let envelope = key
                .encrypt(br#"{"hello":"encrypted"}"#, &iv)
                .expect("encrypts");
            serde_json::to_value(&envelope).expect("serializes")
        };

        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/auth/mfa"))
                    .and(matchers::method("POST"))
                    // The request body is an opdata envelope, not the plaintext params.
                    .and(matchers::body_partial_json(
                        json!({"kid": "SESSION", "enc": "A256GCM"}),
                    ))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
                    .expect(1),
            )
            .await;

        let response: Greeting = client(&server)
            .post_encrypted_json("v1/auth/mfa", json!({"totp": {"code": "123456"}}), &key)
            .await
            .expect("request succeeds");

        assert_eq!(response.hello, "encrypted");
        server.verify().await;
    }

    #[tokio::test]
    async fn surfaces_errors_hidden_inside_an_encrypted_response() {
        let key = session_key();
        let response_body = {
            let mut iv = [0u8; IV_SIZE];
            bitwarden_random::rng().fill_bytes(&mut iv);
            let envelope = key
                .encrypt(br#"{"errorCode":102,"errorMessage":"nope"}"#, &iv)
                .expect("encrypts");
            serde_json::to_value(&envelope).expect("serializes")
        };

        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/auth/mfa"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
                    .expect(1),
            )
            .await;

        let error = client(&server)
            .post_encrypted_json::<Greeting>("v1/auth/mfa", json!({}), &key)
            .await
            .expect_err("encrypted error is surfaced");

        assert!(matches!(error, OnePasswordError::BadCredentials));
        server.verify().await;
    }
}
