use std::sync::Arc;

use bitwarden_crypto::KeyConnectorKey;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiError, client::internal::InternalClient};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum KeyConnectorApiError {
    #[error("Invalid Key Connector URL")]
    InvalidKeyConnectorUrl,
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Client for interacting with the Key Connector API.
pub struct KeyConnectorApiClient {
    #[doc(hidden)]
    internal_client: Arc<InternalClient>,
    /// The base URL of the Key Connector API.
    key_connector_url: String,
}

#[cfg_attr(test, mockall::automock)]
impl KeyConnectorApiClient {
    /// Create a new Key Connector API client.
    pub fn new(internal_client: &Arc<InternalClient>, key_connector_url: &str) -> Self {
        Self {
            internal_client: Arc::clone(internal_client),
            key_connector_url: key_connector_url.to_string(),
        }
    }

    /// Sends the key connector key to the Key Connector API.
    /// If a key already exists, it will be updated; otherwise, a new key will be created for the
    /// user.
    pub async fn post_or_put_key_connector_key(
        &self,
        key_connector_key: &KeyConnectorKey,
    ) -> Result<(), KeyConnectorApiError> {
        let request = KeyConnectorKeyRequestModel {
            key: key_connector_key.to_base64().to_string(),
        };

        if self.get_key_connector_user_keys().await.is_ok() {
            self.put_key_connector_user_keys(request).await?;
        } else {
            self.post_key_connector_user_keys(request).await?;
        }

        Ok(())
    }

    async fn get_key_connector_user_keys(
        &self,
    ) -> Result<KeyConnectorKeyResponseModel, KeyConnectorApiError> {
        let response = request_key_connector_user_keys(
            &self.internal_client,
            Method::GET,
            &self.key_connector_url,
            None::<()>,
        )
        .await?;

        let body = response.text().await.map_err(KeyConnectorApiError::from)?;
        let response_model = serde_json::from_str::<KeyConnectorKeyResponseModel>(&body)?;
        Ok(response_model)
    }

    async fn post_key_connector_user_keys(
        &self,
        request_model: KeyConnectorKeyRequestModel,
    ) -> Result<(), KeyConnectorApiError> {
        request_key_connector_user_keys(
            &self.internal_client,
            Method::POST,
            &self.key_connector_url,
            Some(request_model),
        )
        .await?;

        Ok(())
    }

    async fn put_key_connector_user_keys(
        &self,
        request_model: KeyConnectorKeyRequestModel,
    ) -> Result<(), KeyConnectorApiError> {
        request_key_connector_user_keys(
            &self.internal_client,
            Method::PUT,
            &self.key_connector_url,
            Some(request_model),
        )
        .await?;

        Ok(())
    }
}

async fn request_key_connector_user_keys(
    client: &InternalClient,
    method: Method,
    key_connector_url: &str,
    body: Option<impl Serialize>,
) -> Result<reqwest::Response, KeyConnectorApiError> {
    let url = format!("{}/user-keys", key_connector_url);

    let config = client.get_api_configurations().await;
    let mut request = client
        .get_http_client()
        .request(method, url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json");

    if let Some(ref user_agent) = config.api_config.user_agent {
        request = request.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref access_token) = config.api_config.oauth_access_token {
        request = request.bearer_auth(access_token.clone());
    }
    if let Some(ref body) = body {
        request =
            request.body(serde_json::to_string(&body).expect("Serialize should be infallible"))
    }

    let response = request.send().await.map_err(KeyConnectorApiError::from)?;

    Ok(response.error_for_status()?)
}

impl From<reqwest::Error> for KeyConnectorApiError {
    fn from(e: reqwest::Error) -> Self {
        KeyConnectorApiError::Api(ApiError::Reqwest(e))
    }
}

impl From<serde_json::Error> for KeyConnectorApiError {
    fn from(e: serde_json::Error) -> Self {
        KeyConnectorApiError::Api(ApiError::Serde(e))
    }
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct KeyConnectorKeyRequestModel {
    #[serde(rename = "key", alias = "Key")]
    pub key: String,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct KeyConnectorKeyResponseModel {
    #[serde(rename = "key", alias = "Key")]
    pub key: String,
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;
    use crate::{Client, ClientSettings, DeviceType};

    const ACCESS_TOKEN: &str = "test_access_token";

    async fn setup_mock_server_with_auth() -> (MockServer, Client) {
        let server = MockServer::start().await;

        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", server.address()),
            api_url: format!("http://{}/api", server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
            bitwarden_client_version: None,
        };

        let client = Client::new(Some(settings));

        // Set up authentication token
        client
            .internal
            .set_tokens(ACCESS_TOKEN.to_string(), None, 3600);

        (server, client)
    }

    #[tokio::test]
    async fn test_post_when_key_doesnt_exist() {
        let (server, client) = setup_mock_server_with_auth().await;
        let key_connector_url = format!("http://{}", server.address());

        // Mock GET to return 404 (key doesn't exist)
        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        // Mock POST to succeed
        Mock::given(method("POST"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let key = KeyConnectorKey::make();
        let key_connector_api =
            KeyConnectorApiClient::new(&client.internal, key_connector_url.as_str());
        let result = key_connector_api.post_or_put_key_connector_key(&key).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_put_when_key_exists() {
        let (server, client) = setup_mock_server_with_auth().await;
        let key_connector_url = format!("http://{}", server.address());

        // Mock GET to return 200 (key exists)
        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key": "existing_key_connector_key"
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Mock PUT to succeed
        Mock::given(method("PUT"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let key = KeyConnectorKey::make();
        let key_connector_api =
            KeyConnectorApiClient::new(&client.internal, key_connector_url.as_str());
        let result = key_connector_api.post_or_put_key_connector_key(&key).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_error_when_both_get_and_post_fail() {
        let (server, client) = setup_mock_server_with_auth().await;
        let key_connector_url = format!("http://{}", server.address());

        // Mock GET to return 500 (server error)
        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        // Mock POST to also fail (since GET failed, POST will be attempted)
        Mock::given(method("POST"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let key = KeyConnectorKey::make();
        let key_connector_api =
            KeyConnectorApiClient::new(&client.internal, key_connector_url.as_str());
        let result = key_connector_api.post_or_put_key_connector_key(&key).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyConnectorApiError::Api(_)));
    }

    #[tokio::test]
    async fn test_error_when_post_fails() {
        let (server, client) = setup_mock_server_with_auth().await;
        let key_connector_url = format!("http://{}", server.address());

        // Mock GET to return 404 (key doesn't exist)
        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        // Mock POST to fail with 500
        Mock::given(method("POST"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let key = KeyConnectorKey::make();
        let key_connector_api =
            KeyConnectorApiClient::new(&client.internal, key_connector_url.as_str());
        let result = key_connector_api.post_or_put_key_connector_key(&key).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyConnectorApiError::Api(_)));
    }

    #[tokio::test]
    async fn test_error_when_put_fails() {
        let (server, client) = setup_mock_server_with_auth().await;
        let key_connector_url = format!("http://{}", server.address());

        // Mock GET to return 200 (key exists)
        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key": "existing_key_connector_key"
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Mock PUT to fail with 500
        Mock::given(method("PUT"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let key = KeyConnectorKey::make();
        let key_connector_api =
            KeyConnectorApiClient::new(&client.internal, key_connector_url.as_str());
        let result = key_connector_api.post_or_put_key_connector_key(&key).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyConnectorApiError::Api(_)));
    }
}
