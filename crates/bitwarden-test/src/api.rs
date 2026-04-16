use bitwarden_api_api::Configuration;

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
        client: reqwest::Client::new().into(),
    };

    (server, config)
}
