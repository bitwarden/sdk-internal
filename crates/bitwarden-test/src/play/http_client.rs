//! HTTP client with automatic x-play-id header injection

use reqwest::{Client, RequestBuilder, Response};
use serde::{Serialize, de::DeserializeOwned};
use tracing::debug;

use super::{PlayConfig, PlayError, PlayResult};

/// HTTP client wrapper that adds the x-play-id header to all requests
#[derive(Debug, Clone)]
pub struct PlayHttpClient {
    client: Client,
    play_id: String,
    config: PlayConfig,
}

impl PlayHttpClient {
    /// Create a new HTTP client with the given play_id
    pub fn new(play_id: String, config: PlayConfig) -> Self {
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
    pub fn play_id(&self) -> &str {
        &self.play_id
    }

    /// Get the configuration
    pub fn config(&self) -> &PlayConfig {
        &self.config
    }

    /// Add the x-play-id header to a request builder
    fn with_play_id(&self, builder: RequestBuilder) -> RequestBuilder {
        builder.header("x-play-id", &self.play_id)
    }

    /// POST JSON to the seeder API and parse JSON response
    pub async fn post_seeder<T: Serialize, R: DeserializeOwned>(
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
    pub async fn delete_seeder(&self, path: &str) -> PlayResult<()> {
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
