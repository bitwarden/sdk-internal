use std::time::Duration;

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::{auth::TokenHandler, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;
use wiremock::MockServer;

/// Start a mock server that accepts any request with a 200 response.
pub async fn start_app_server() -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Start a mock app server that returns 401 for requests carrying `stale_token`
/// in the Authorization header and 200 for any other request. Useful for exercising
/// the middleware's retry-on-401 path.
pub async fn start_app_server_rejecting(stale_token: &str) -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::header(
        "Authorization",
        format!("Bearer {stale_token}").as_str(),
    ))
    .respond_with(wiremock::ResponseTemplate::new(401))
    .mount(&server)
    .await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Start a mock app server that returns 200 for requests carrying `valid_token` in the
/// Authorization header and 401 for everything else (including unauthenticated requests).
pub async fn start_app_server_accepting(valid_token: &str) -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::header(
        "Authorization",
        format!("Bearer {valid_token}").as_str(),
    ))
    .respond_with(wiremock::ResponseTemplate::new(200))
    .mount(&server)
    .await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(401))
        .mount(&server)
        .await;
    server
}

/// Start a mock identity server that returns a renewed token on POST /connect/token.
pub async fn start_renewal_server(renewed_token: &str) -> MockServer {
    start_renewal_server_with_delay(renewed_token, Duration::ZERO).await
}

/// Start a mock identity server that returns a renewed token after the given delay.
/// Useful for exercising concurrent renewal paths.
pub async fn start_renewal_server_with_delay(renewed_token: &str, delay: Duration) -> MockServer {
    let server = MockServer::start().await;
    mount_renewal_response(&server, renewed_token, delay).await;
    server
}

/// Start a mock identity server that fails the first POST /connect/token with 500 and then
/// returns a renewed token on subsequent requests.
pub async fn start_renewal_server_failing_then_succeeding(renewed_token: &str) -> MockServer {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/connect/token"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_renewal_response(&server, renewed_token, Duration::ZERO).await;
    server
}

async fn mount_renewal_response(server: &MockServer, renewed_token: &str, delay: Duration) {
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/connect/token"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(serde_json::json!({
                    "access_token": renewed_token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "api"
                })),
        )
        .mount(server)
        .await;
}

/// Initialize the handler's middleware against `registry` and `identity_server`, then wrap it in
/// a [reqwest_middleware::ClientWithMiddleware] suitable for sending test requests.
pub fn build_client<H: TokenHandler>(
    handler: &H,
    registry: &StateRegistry,
    identity_server: &MockServer,
) -> reqwest_middleware::ClientWithMiddleware {
    let middleware = handler.initialize_middleware(
        registry,
        bitwarden_api_api::Configuration::new(identity_server.uri()),
        KeyStore::<KeySlotIds>::default(),
    );
    reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with_arc(middleware)
        .build()
}

/// Spawn `count` concurrent authenticated GET requests against `app_server` and assert all
/// responses return 200. Useful for exercising the middleware's renewal serialization.
pub async fn send_concurrent_auth_requests(
    client: &reqwest_middleware::ClientWithMiddleware,
    app_server: &MockServer,
    count: usize,
) {
    let mut handles = Vec::with_capacity(count);
    for _ in 0..count {
        let client = client.clone();
        let url = format!("{}/test", app_server.uri());
        handles.push(tokio::spawn(async move {
            client
                .get(url)
                .with_extension(AuthRequired::Bearer)
                .send()
                .await
                .unwrap()
        }));
    }
    for handle in handles {
        let response = handle.await.unwrap();
        assert_eq!(response.status(), 200);
    }
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
