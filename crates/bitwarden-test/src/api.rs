use bitwarden_api_api::apis::configuration::Configuration;

/// Helper for testing the Bitwarden API using wiremock.
///
/// Warning: when using `Mock::expected` ensure `server` is not dropped before the test completes,
pub async fn start_api_mock(mocks: Vec<wiremock::Mock>) -> (wiremock::MockServer, Configuration) {
    let server = wiremock::MockServer::start().await;

    for mock in mocks {
        server.register(mock).await;
    }

    let config = Configuration {
        base_path: server.uri(),
        user_agent: Some("test-agent".to_string()),
        client: reqwest::Client::new(),
        basic_auth: None,
        oauth_access_token: None,
        bearer_access_token: None,
        api_key: None,
    };

    (server, config)
}
