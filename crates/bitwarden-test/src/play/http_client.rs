//! HTTP client with automatic x-play-id header injection

use reqwest::{Client, RequestBuilder, Response};
use serde::{Serialize, de::DeserializeOwned};
use tracing::debug;

use super::{PlayConfig, PlayError, PlayResult};

/// HTTP client wrapper that adds the x-play-id header to all requests
#[derive(Debug, Clone)]
pub(crate) struct PlayHttpClient {
    client: Client,
    play_id: String,
    config: PlayConfig,
}

impl PlayHttpClient {
    /// Create a new HTTP client with the given play_id
    pub(crate) fn new(play_id: String, config: PlayConfig) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            play_id,
            config,
        }
    }

    /// Get the play_id for this client
    pub(crate) fn play_id(&self) -> &str {
        &self.play_id
    }

    /// Get the configuration
    pub(crate) fn config(&self) -> &PlayConfig {
        &self.config
    }

    /// Add the x-play-id header to a request builder
    fn with_play_id(&self, builder: RequestBuilder) -> RequestBuilder {
        builder.header("x-play-id", &self.play_id)
    }

    /// POST JSON to the seeder API and parse JSON response
    pub(crate) async fn post_seeder<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> PlayResult<R> {
        let url = format!("{}{}", self.config.seeder_url, path);

        debug!(
            method = "POST",
            url = %url,
            play_id = %self.play_id,
            body = ?serde_json::to_string(body).ok(),
            "Play request"
        );

        let response = self
            .with_play_id(self.client.post(&url))
            .json(body)
            .send()
            .await?;

        self.handle_json_response(response).await
    }

    /// DELETE to the seeder API
    pub(crate) async fn delete_seeder(&self, path: &str) -> PlayResult<()> {
        let url = format!("{}{}", self.config.seeder_url, path);

        debug!(
            method = "DELETE",
            url = %url,
            play_id = %self.play_id,
            "Play request"
        );

        let response = self.with_play_id(self.client.delete(&url)).send().await?;

        let status = response.status();
        debug!(status = %status, "Play response");

        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            debug!(body = %body, "Play error response body");
            Err(PlayError::ServerError {
                status: status.as_u16(),
                body,
            })
        }
    }

    /// Handle a JSON response, returning an error for non-success status codes
    async fn handle_json_response<R: DeserializeOwned>(&self, response: Response) -> PlayResult<R> {
        let status = response.status();

        if status.is_success() {
            let body = response.text().await?;
            debug!(status = %status, body = %body, "Play response");
            Ok(serde_json::from_str(&body)?)
        } else {
            let body = response.text().await.unwrap_or_default();
            debug!(status = %status, body = %body, "Play error response");
            Err(PlayError::ServerError {
                status: status.as_u16(),
                body,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    fn create_test_config(seeder_url: &str) -> PlayConfig {
        PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            seeder_url,
        )
    }

    #[test]
    fn test_new_stores_play_id_and_config() {
        let config = create_test_config("http://localhost:5047");
        let client = PlayHttpClient::new("test-play-id".to_string(), config);

        assert_eq!(client.play_id(), "test-play-id");
        assert_eq!(client.config().api_url, "https://api.example.com");
        assert_eq!(client.config().identity_url, "https://identity.example.com");
        assert_eq!(client.config().seeder_url, "http://localhost:5047");
    }

    #[tokio::test]
    async fn test_post_seeder() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/seed/"))
            .and(header("x-play-id", "test-play-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "name": "test-user"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let client = PlayHttpClient::new("test-play-id".to_string(), config);

        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct TestResponse {
            id: i32,
            name: String,
        }

        let result: TestResponse = client
            .post_seeder("/seed/", &serde_json::json!({}))
            .await
            .unwrap();

        assert_eq!(result.id, 42);
        assert_eq!(result.name, "test-user");
    }

    #[tokio::test]
    async fn test_post_seeder_handles_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/seed/"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let client = PlayHttpClient::new("test-id".to_string(), config);

        let result: PlayResult<serde_json::Value> =
            client.post_seeder("/seed/", &serde_json::json!({})).await;

        match result {
            Err(PlayError::ServerError { status, body }) => {
                assert_eq!(status, 500);
                assert_eq!(body, "Internal Server Error");
            }
            _ => panic!("Expected ServerError"),
        }
    }

    #[tokio::test]
    async fn test_delete_seeder_sends_correct_request() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/seed/test-play-id"))
            .and(header("x-play-id", "test-play-id"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let client = PlayHttpClient::new("test-play-id".to_string(), config);

        let result = client.delete_seeder("/seed/test-play-id").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_seeder_handles_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/seed/test-id"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let client = PlayHttpClient::new("test-id".to_string(), config);

        let result = client.delete_seeder("/seed/test-id").await;

        match result {
            Err(PlayError::ServerError { status, body }) => {
                assert_eq!(status, 404);
                assert_eq!(body, "Not found");
            }
            _ => panic!("Expected ServerError"),
        }
    }
}
