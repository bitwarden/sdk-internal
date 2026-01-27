use std::sync::Arc;

use async_trait::async_trait;
use configuration::Configuration;
use mockall::automock;
use reqwest::Method;
use serde::Serialize;

use crate::{
    apis::{Error, configuration},
    models::{
        user_key_request_model::UserKeyKeyRequestModel,
        user_key_response_model::UserKeyResponseModel,
    },
};

#[automock]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait UserKeysApi: Send + Sync {
    /// GET /user-keys
    async fn get_user_key(&self) -> Result<UserKeyResponseModel, Error>;

    /// POST /user-keys
    async fn post_user_key(&self, request_model: UserKeyKeyRequestModel) -> Result<(), Error>;

    /// PUT /user-keys
    async fn put_user_key(&self, request_model: UserKeyKeyRequestModel) -> Result<(), Error>;
}

pub struct UserKeysApiClient {
    configuration: Arc<Configuration>,
}

impl UserKeysApiClient {
    pub fn new(configuration: Arc<Configuration>) -> Self {
        Self { configuration }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl UserKeysApi for UserKeysApiClient {
    async fn get_user_key(&self) -> Result<UserKeyResponseModel, Error> {
        let response = request(&self.configuration, Method::GET, None::<()>).await?;

        let body = response.text().await?;
        let response_model = serde_json::from_str::<UserKeyResponseModel>(&body)?;
        Ok(response_model)
    }

    async fn post_user_key(&self, request_model: UserKeyKeyRequestModel) -> Result<(), Error> {
        request(&self.configuration, Method::POST, Some(request_model)).await?;

        Ok(())
    }

    async fn put_user_key(&self, request_model: UserKeyKeyRequestModel) -> Result<(), Error> {
        request(&self.configuration, Method::PUT, Some(request_model)).await?;

        Ok(())
    }
}

async fn request(
    configuration: &Arc<Configuration>,
    method: Method,
    body: Option<impl Serialize>,
) -> Result<reqwest::Response, Error> {
    let url = format!("{}/user-keys", configuration.base_path);

    let mut request = configuration
        .client
        .request(method, url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json");

    if let Some(ref user_agent) = configuration.user_agent {
        request = request.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref access_token) = configuration.oauth_access_token {
        request = request.bearer_auth(access_token.clone());
    }
    if let Some(ref body) = body {
        request =
            request.body(serde_json::to_string(&body).expect("Serialize should be infallible"))
    }

    let response = request.send().await?;

    Ok(response.error_for_status()?)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use crate::{
        apis::{
            configuration::Configuration,
            user_keys_api::{UserKeysApi, UserKeysApiClient},
        },
        models::user_key_request_model::UserKeyKeyRequestModel,
    };

    const ACCESS_TOKEN: &str = "test_access_token";
    const KEY_CONNECTOR_KEY: &str = "test_key_connector_key";

    async fn setup_mock_server_with_auth() -> (MockServer, Configuration) {
        let server = MockServer::start().await;

        let configuration = Configuration {
            base_path: format!("http://{}", server.address()),
            user_agent: Some("Bitwarden Rust-SDK [TEST]".to_string()),
            client: reqwest::Client::new().into(),
            oauth_access_token: Some(ACCESS_TOKEN.to_string()),
        };

        (server, configuration)
    }

    #[tokio::test]
    async fn test_get() {
        let (server, configuration) = setup_mock_server_with_auth().await;

        Mock::given(method("GET"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key": KEY_CONNECTOR_KEY.to_string()
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api_client = UserKeysApiClient::new(Arc::new(configuration));

        let result = api_client.get_user_key().await;

        assert!(result.is_ok());
        assert_eq!(KEY_CONNECTOR_KEY, result.unwrap().key);
    }

    #[tokio::test]
    async fn test_post() {
        let (server, configuration) = setup_mock_server_with_auth().await;

        Mock::given(method("POST"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let request_model = UserKeyKeyRequestModel {
            key: KEY_CONNECTOR_KEY.to_string(),
        };

        let api_client = UserKeysApiClient::new(Arc::new(configuration));

        let result = api_client.post_user_key(request_model).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_put() {
        let (server, configuration) = setup_mock_server_with_auth().await;

        Mock::given(method("PUT"))
            .and(path("/user-keys"))
            .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let request_model = UserKeyKeyRequestModel {
            key: KEY_CONNECTOR_KEY.to_string(),
        };

        let api_client = UserKeysApiClient::new(Arc::new(configuration));

        let result = api_client.put_user_key(request_model).await;

        assert!(result.is_ok());
    }
}
