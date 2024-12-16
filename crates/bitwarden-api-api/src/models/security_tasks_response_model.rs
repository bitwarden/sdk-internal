/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityTasksResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<uuid::Uuid>,
    #[serde(rename = "cipherId", skip_serializing_if = "Option::is_none")]
    pub cipher_id: Option<uuid::Uuid>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<models::SecurityTaskType>,
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<models::SecurityTaskStatus>,
    #[serde(rename = "creationDate", skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    #[serde(rename = "revisionDate", skip_serializing_if = "Option::is_none")]
    pub revision_date: Option<String>,
}

impl SecurityTasksResponseModel {
    pub fn new() -> SecurityTasksResponseModel {
        SecurityTasksResponseModel {
            object: None,
            id: None,
            organization_id: None,
            cipher_id: None,
            r#type: None,
            status: None,
            creation_date: None,
            revision_date: None,
        }
    }
}