use bitwarden_crypto::KeyConnectorKey;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiError, Client};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum KeyConnectorApiError {
    #[error("Invalid Key Connector URL")]
    InvalidKeyConnectorUrl,
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Sends the key connector key to the Key Connector API.
/// If a key already exists, it will be updated; otherwise, a new key will be created for the user.
pub async fn key_connector_api_post_or_put_key_connector_key(
    client: &Client,
    key_connector_url: &str,
    key_connector_key: &KeyConnectorKey,
) -> Result<(), KeyConnectorApiError> {
    let request = KeyConnectorKeyRequestModel {
        key: key_connector_key.to_base64().to_string(),
    };

    if get_key_connector_user_keys(client, key_connector_url)
        .await
        .is_ok()
    {
        put_key_connector_user_keys(client, key_connector_url, request).await?;
    } else {
        post_key_connector_user_keys(client, key_connector_url, request).await?;
    }

    Ok(())
}

async fn get_key_connector_user_keys(
    client: &Client,
    key_connector_url: &str,
) -> Result<KeyConnectorKeyResponseModel, KeyConnectorApiError> {
    let response =
        request_key_connector_user_keys(client, Method::GET, key_connector_url, None::<()>).await?;

    let body = response.text().await.map_err(KeyConnectorApiError::from)?;
    let response_model = serde_json::from_str::<KeyConnectorKeyResponseModel>(&body)?;
    Ok(response_model)
}

async fn post_key_connector_user_keys(
    client: &Client,
    key_connector_url: &str,
    request_model: KeyConnectorKeyRequestModel,
) -> Result<(), KeyConnectorApiError> {
    request_key_connector_user_keys(client, Method::POST, key_connector_url, Some(request_model))
        .await?;

    Ok(())
}

async fn put_key_connector_user_keys(
    client: &Client,
    key_connector_url: &str,
    request_model: KeyConnectorKeyRequestModel,
) -> Result<(), KeyConnectorApiError> {
    request_key_connector_user_keys(client, Method::PUT, key_connector_url, Some(request_model))
        .await?;

    Ok(())
}

async fn request_key_connector_user_keys(
    client: &Client,
    method: Method,
    key_connector_url: &str,
    body: Option<impl Serialize>,
) -> Result<reqwest::Response, KeyConnectorApiError> {
    let url = format!("{}/user-keys", key_connector_url);

    let config = client.internal.get_api_configurations().await;
    let mut request = client
        .internal
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
