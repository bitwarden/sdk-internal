use std::sync::Arc;

use bitwarden_api_api::apis::AuthRequired;
use wiremock::MockServer;

pub fn identity_config(server_uri: &str) -> bitwarden_api_api::Configuration {
    bitwarden_api_api::Configuration {
        base_path: server_uri.to_string(),
        client: reqwest::Client::new().into(),
        oauth_access_token: None,
        user_agent: None,
    }
}

/// Start a mock server that accepts any request with a 200 response.
pub async fn start_app_server() -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Start a mock identity server that returns a renewed token on POST /connect/token.
pub async fn start_renewal_server(renewed_token: &str) -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/connect/token"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": renewed_token,
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "api"
            })),
        )
        .mount(&server)
        .await;
    server
}

pub fn build_client(
    middleware: Arc<dyn reqwest_middleware::Middleware>,
) -> reqwest_middleware::ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with_arc(middleware)
        .build()
}

/// Send an authenticated request to the app server and return the Authorization
/// header value that reached the server.
pub async fn send_auth_request(
    client: &reqwest_middleware::ClientWithMiddleware,
    app_server: &MockServer,
) -> Option<String> {
    client
        .get(format!("{}/test", app_server.uri()))
        .with_extension(AuthRequired::Bearer)
        .send()
        .await
        .unwrap();

    let requests = app_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    requests[0]
        .headers
        .get("Authorization")
        .map(|v| v.to_str().unwrap().to_string())
}
