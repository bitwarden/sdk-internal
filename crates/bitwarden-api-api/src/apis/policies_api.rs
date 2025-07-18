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

/// struct for typed errors of method [`organizations_org_id_policies_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`organizations_org_id_policies_invited_user_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesInvitedUserGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`organizations_org_id_policies_master_password_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesMasterPasswordGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`organizations_org_id_policies_token_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesTokenGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`organizations_org_id_policies_type_get`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesTypeGetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`organizations_org_id_policies_type_put`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OrganizationsOrgIdPoliciesTypePutError {
    UnknownValue(serde_json::Value),
}

pub async fn organizations_org_id_policies_get(
    configuration: &configuration::Configuration,
    org_id: &str,
) -> Result<models::PolicyResponseModelListResponseModel, Error<OrganizationsOrgIdPoliciesGetError>>
{
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;

    let uri_str = format!(
        "{}/organizations/{orgId}/policies",
        configuration.base_path,
        orgId = crate::apis::urlencode(p_org_id)
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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesGetError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn organizations_org_id_policies_invited_user_get(
    configuration: &configuration::Configuration,
    org_id: uuid::Uuid,
    user_id: Option<uuid::Uuid>,
) -> Result<
    models::PolicyResponseModelListResponseModel,
    Error<OrganizationsOrgIdPoliciesInvitedUserGetError>,
> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;
    let p_user_id = user_id;

    let uri_str = format!(
        "{}/organizations/{orgId}/policies/invited-user",
        configuration.base_path,
        orgId = crate::apis::urlencode(p_org_id.to_string())
    );
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref param_value) = p_user_id {
        req_builder = req_builder.query(&[("userId", &param_value.to_string())]);
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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesInvitedUserGetError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn organizations_org_id_policies_master_password_get(
    configuration: &configuration::Configuration,
    org_id: uuid::Uuid,
) -> Result<models::PolicyResponseModel, Error<OrganizationsOrgIdPoliciesMasterPasswordGetError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;

    let uri_str = format!(
        "{}/organizations/{orgId}/policies/master-password",
        configuration.base_path,
        orgId = crate::apis::urlencode(p_org_id.to_string())
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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesMasterPasswordGetError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn organizations_org_id_policies_token_get(
    configuration: &configuration::Configuration,
    org_id: uuid::Uuid,
    email: Option<&str>,
    token: Option<&str>,
    organization_user_id: Option<uuid::Uuid>,
) -> Result<
    models::PolicyResponseModelListResponseModel,
    Error<OrganizationsOrgIdPoliciesTokenGetError>,
> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;
    let p_email = email;
    let p_token = token;
    let p_organization_user_id = organization_user_id;

    let uri_str = format!(
        "{}/organizations/{orgId}/policies/token",
        configuration.base_path,
        orgId = crate::apis::urlencode(p_org_id.to_string())
    );
    let mut req_builder = configuration.client.request(reqwest::Method::GET, &uri_str);

    if let Some(ref param_value) = p_email {
        req_builder = req_builder.query(&[("email", &param_value.to_string())]);
    }
    if let Some(ref param_value) = p_token {
        req_builder = req_builder.query(&[("token", &param_value.to_string())]);
    }
    if let Some(ref param_value) = p_organization_user_id {
        req_builder = req_builder.query(&[("organizationUserId", &param_value.to_string())]);
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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyResponseModelListResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesTokenGetError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn organizations_org_id_policies_type_get(
    configuration: &configuration::Configuration,
    org_id: uuid::Uuid,
    r#type: i32,
) -> Result<models::PolicyDetailResponseModel, Error<OrganizationsOrgIdPoliciesTypeGetError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;
    let p_type = r#type;

    let uri_str = format!("{}/organizations/{orgId}/policies/{type}", configuration.base_path, orgId=crate::apis::urlencode(p_org_id.to_string()), type=p_type);
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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyDetailResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyDetailResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesTypeGetError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}

pub async fn organizations_org_id_policies_type_put(
    configuration: &configuration::Configuration,
    org_id: uuid::Uuid,
    r#type: models::PolicyType,
    policy_request_model: Option<models::PolicyRequestModel>,
) -> Result<models::PolicyResponseModel, Error<OrganizationsOrgIdPoliciesTypePutError>> {
    // add a prefix to parameters to efficiently prevent name collisions
    let p_org_id = org_id;
    let p_type = r#type;
    let p_policy_request_model = policy_request_model;

    let uri_str = format!("{}/organizations/{orgId}/policies/{type}", configuration.base_path, orgId=crate::apis::urlencode(p_org_id.to_string()), type=p_type.to_string());
    let mut req_builder = configuration.client.request(reqwest::Method::PUT, &uri_str);

    if let Some(ref user_agent) = configuration.user_agent {
        req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent.clone());
    }
    if let Some(ref token) = configuration.oauth_access_token {
        req_builder = req_builder.bearer_auth(token.to_owned());
    };
    req_builder = req_builder.json(&p_policy_request_model);

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
            ContentType::Text => return Err(Error::from(serde_json::Error::custom("Received `text/plain` content type response that cannot be converted to `models::PolicyResponseModel`"))),
            ContentType::Unsupported(unknown_type) => return Err(Error::from(serde_json::Error::custom(format!("Received `{unknown_type}` content type response that cannot be converted to `models::PolicyResponseModel`")))),
        }
    } else {
        let content = resp.text().await?;
        let entity: Option<OrganizationsOrgIdPoliciesTypePutError> =
            serde_json::from_str(&content).ok();
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity,
        }))
    }
}
