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
pub struct OrganizationUserUserMiniDetailsResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<uuid::Uuid>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<models::OrganizationUserType>,
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<models::OrganizationUserStatusType>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl OrganizationUserUserMiniDetailsResponseModel {
    pub fn new() -> OrganizationUserUserMiniDetailsResponseModel {
        OrganizationUserUserMiniDetailsResponseModel {
            object: None,
            id: None,
            user_id: None,
            r#type: None,
            status: None,
            name: None,
            email: None,
        }
    }
}