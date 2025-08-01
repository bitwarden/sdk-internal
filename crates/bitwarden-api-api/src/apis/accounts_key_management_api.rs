/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use reqwest;
use serde::{de::Error as _, Deserialize, Serialize};

use super::{configuration, ContentType, Error};
use crate::{apis::ResponseContent, models};

/// struct for typed errors of method [`accounts_convert_to_key_connector_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountsConvertToKeyConnectorPostError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`accounts_key_management_regenerate_keys_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountsKeyManagementRegenerateKeysPostError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`accounts_key_management_rotate_user_account_keys_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountsKeyManagementRotateUserAccountKeysPostError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`accounts_set_key_connector_key_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountsSetKeyConnectorKeyPostError {
    UnknownValue(serde_json::Value),
}

pub async fn accounts_convert_to_key_connector_post(
    configuration: &configuration::Configuration,
) -> Result<(), Error<AccountsConvertToKeyConnectorPostError>> {
    let uri_str = format!(
        "{}/accounts/convert-to-key-connector",
        configuration.base_path
    );
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();

    if !status.is_client_error() && !status.is_server_error() {
        Ok(())
    } else {
        let content = resp.text().await?;
        let entity: Option<AccountsConvertToKeyConnectorPostError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn accounts_key_management_regenerate_keys_post(
    configuration: &configuration::Configuration,
    key_regeneration_request_model: Option<models::KeyRegenerationRequestModel>,
) -> Result<(), Error<AccountsKeyManagementRegenerateKeysPostError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_key_regeneration_request_model = key_regeneration_request_model;

    let uri_str = format!(
        "{}/accounts/key-management/regenerate-keys",
        configuration.base_path
    );
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_key_regeneration_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();

    if !status.is_client_error() && !status.is_server_error() {
        Ok(())
    } else {
        let content = resp.text().await?;
        let entity: Option<AccountsKeyManagementRegenerateKeysPostError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn accounts_key_management_rotate_user_account_keys_post(
    configuration: &configuration::Configuration,
    rotate_user_account_keys_and_data_request_model: Option<
        models::RotateUserAccountKeysAndDataRequestModel,
    >,
) -> Result<(), Error<AccountsKeyManagementRotateUserAccountKeysPostError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_rotate_user_account_keys_and_data_request_model =
        rotate_user_account_keys_and_data_request_model;

    let uri_str = format!(
        "{}/accounts/key-management/rotate-user-account-keys",
        configuration.base_path
    );
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_rotate_user_account_keys_and_data_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();

    if !status.is_client_error() && !status.is_server_error() {
        Ok(())
    } else {
        let content = resp.text().await?;
        let entity: Option<AccountsKeyManagementRotateUserAccountKeysPostError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn accounts_set_key_connector_key_post(
    configuration: &configuration::Configuration,
    set_key_connector_key_request_model: Option<models::SetKeyConnectorKeyRequestModel>,
) -> Result<(), Error<AccountsSetKeyConnectorKeyPostError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_set_key_connector_key_request_model = set_key_connector_key_request_model;

    let uri_str = format!("{}/accounts/set-key-connector-key", configuration.base_path);
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_set_key_connector_key_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();

    if !status.is_client_error() && !status.is_server_error() {
        Ok(())
    } else {
        let content = resp.text().await?;
        let entity: Option<AccountsSetKeyConnectorKeyPostError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}
