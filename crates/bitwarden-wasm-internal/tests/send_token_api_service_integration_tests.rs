// TODO: do more to figure out test suite.

use crate::auth::send_access::{
    requests::SendAccessTokenRequest, responses::SendAccessTokenResponse, SendTokenApiService,
};
use crate::auth::AuthClient;
use bitwarden_core::{Client as CoreClient, ClientSettings, DeviceType};
use tokio;
use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn request_send_access_token_success() {
    // spin up mock server
    let mock_server = MockServer::start().await;

    // Build core client with our mock server
    let settings = ClientSettings {
        identity_url: format!("http://{}/identity", mock_server.address()),
        api_url: format!("http://{}/api", mock_server.address()),
        user_agent: "Bitwarden Rust-SDK [TEST]".into(),
        device_type: DeviceType::SDK,
    };

    let core = CoreClient::new(Some(settings));

    // Create auth client with the core client
    let auth_client = AuthClient { client: core };

    // Create a mock send api service
    let service = SendTokenApiService { auth_client };

    // Construct the real Request type
    let req = SendAccessTokenRequest {
        client_id: "test_client_id".into(),
        client_secret: "test_client_secret".into(),
        grant_type: "client_credentials".into(),
    };

    // Create a mock success response
    let fake_response = SendAccessTokenResponse {
        access_token: "token".into(),
        token_type: "bearer".into(),
        expires_in: 3600,
    };

    // Register the mock for the request
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("/connect/token"))
        .and(matchers::header(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=utf-8",
        ))
        .and(matchers::body_json(&req))
        .respond_with(ResponseTemplate::new(200).set_body_json(fake_response));
    mock_server.register(mock).await;

    // Call the service method
    let result = service.request_send_access_token(req).await;
    assert!(result.is_ok());
    let token = result.unwrap();
    assert_eq!(token.access_token, "token");
    assert_eq!(token.token_type, "bearer");
    assert_eq!(token.expires_in, 3600);
}
