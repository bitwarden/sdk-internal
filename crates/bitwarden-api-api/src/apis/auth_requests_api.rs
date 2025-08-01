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

/// struct for typed errors of method [`auth_requests_admin_request_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsAdminRequestPostError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_id_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsIdGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_id_put`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsIdPutError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_id_response_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsIdResponseGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_pending_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsPendingGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`auth_requests_post`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthRequestsPostError {
    UnknownValue(serde_json::Value),
}

pub async fn auth_requests_admin_request_post(
    configuration: &configuration::Configuration,
    auth_request_create_request_model: Option<models::AuthRequestCreateRequestModel>,
) -> Result<models::AuthRequestResponseModel, Error<AuthRequestsAdminRequestPostError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_auth_request_create_request_model = auth_request_create_request_model;

    let uri_str = format!("{}/auth-requests/admin-request", configuration.base_path);
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_auth_request_create_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsAdminRequestPostError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_get(
    configuration: &configuration::Configuration,
) -> Result<models::AuthRequestResponseModelListResponseModel, Error<AuthRequestsGetError>> {
    let uri_str = format!("{}/auth-requests", configuration.base_path);
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModelListResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModelListResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsGetError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_id_get(
    configuration: &configuration::Configuration,
    id: uuid::Uuid,
) -> Result<models::AuthRequestResponseModel, Error<AuthRequestsIdGetError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_id = id;

    let uri_str = format!(
        "{}/auth-requests/{id}",
        configuration.base_path,
        id = crate::apis::urlencode(p_id.to_string())
    );
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsIdGetError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_id_put(
    configuration: &configuration::Configuration,
    id: uuid::Uuid,
    auth_request_update_request_model: Option<models::AuthRequestUpdateRequestModel>,
) -> Result<models::AuthRequestResponseModel, Error<AuthRequestsIdPutError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_id = id;
    let p_auth_request_update_request_model = auth_request_update_request_model;

    let uri_str = format!(
        "{}/auth-requests/{id}",
        configuration.base_path,
        id = crate::apis::urlencode(p_id.to_string())
    );
    let mut req_builder = configuration.client.request(reqwest::Method::PUT, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_auth_request_update_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsIdPutError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_id_response_get(
    configuration: &configuration::Configuration,
    id: uuid::Uuid,
    code: Option<&str>,
) -> Result<models::AuthRequestResponseModel, Error<AuthRequestsIdResponseGetError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_id = id;
    let p_code = code;

    let uri_str = format!(
        "{}/auth-requests/{id}/response",
        configuration.base_path,
        id = crate::apis::urlencode(p_id.to_string())
    );
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref param_value) = p_code {
        req_builder = req_builder.query(&[("code", &param_value.to_string())]);
    }
    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsIdResponseGetError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_pending_get(
    configuration: &configuration::Configuration,
) -> Result<
    models::PendingAuthRequestResponseModelListResponseModel,
    Error<AuthRequestsPendingGetError>,
> {
    let uri_str = format!("{}/auth-requests/pending", configuration.base_path);
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PendingAuthRequestResponseModelListResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PendingAuthRequestResponseModelListResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsPendingGetError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn auth_requests_post(
    configuration: &configuration::Configuration,
    auth_request_create_request_model: Option<models::AuthRequestCreateRequestModel>,
) -> Result<models::AuthRequestResponseModel, Error<AuthRequestsPostError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_auth_request_create_request_model = auth_request_create_request_model;

    let uri_str = format!("{}/auth-requests", configuration.base_path);
    let mut req_builder = configuration
        .client
        .request(reqwest::Method::POST, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_auth_request_create_request_model);

    let req = req_builder.build()?;
    let resp = configuration.client.execute(req).await?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let content_type = super::ContentType::from(content_type);

    if !status.is_client_error() && !status.is_server_error() {
        let content = resp.text().await?;
        match content_type {
            ContentType::Json => serde_json::from_str(&content).map_err(Error::from),
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::AuthRequestResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::AuthRequestResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<AuthRequestsPostError> = serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}
