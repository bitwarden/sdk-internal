use std::sync::Arc;

use bitwarden_core::{
    client::{Client, ClientSettings},
    http::{Cookie, CookieStore, InMemoryCookieStore},
};

#[tokio::test]
async fn test_client_new_internal_with_cookie_middleware() {
    // Verify Client::new() constructs successfully with cookie middleware
    let settings = ClientSettings::default();
    let client = Client::new(Some(settings));

    // Client construction should succeed (middleware chain compiled)
    // This is a smoke test - actual HTTP request test follows
    assert!(
        client
            .internal
            .api_configurations
            .api
            .client
            .inner()
            .is_ok()
    );
}

#[tokio::test]
async fn test_cookie_middleware_integration_with_store() {
    // This test verifies the cookie store can be accessed and cookies retrieved
    // Full HTTP integration requires mock server setup (future work)

    let store = Arc::new(InMemoryCookieStore::new());
    let cookie = Cookie::new("integration_test", "value123");

    store.set_cookie(cookie.clone()).await.unwrap();

    let retrieved = store.get_cookie("integration_test").await.unwrap();
    assert_eq!(retrieved, Some(cookie));

    // Verify cookie formatted correctly for header
    let header_value = retrieved.unwrap().to_cookie_header();
    assert_eq!(header_value, "integration_test=value123");
}

// NOTE: Full middleware chain integration test with real HTTP requests requires
// mock server setup (wiremock or similar). This would verify:
// 1. Cookie header actually injected into request
// 2. Authorization header from auth middleware also present
// 3. Middleware order correct (auth before cookie)
//
// Recommended future test:
// #[tokio::test]
// async fn test_real_http_request_includes_cookies() {
//     let mock_server = MockServer::start().await;
//     // Setup mock endpoint, make request, verify headers
// }
