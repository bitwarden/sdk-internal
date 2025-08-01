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
pub struct MemberCipherDetailsResponseModel {
    #[serde(rename = "userGuid", skip_serializing_if = "Option::is_none")]
    pub user_guid: Option<uuid::Uuid>,
    #[serde(rename = "userName", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "usesKeyConnector", skip_serializing_if = "Option::is_none")]
    pub uses_key_connector: Option<bool>,
    /// A distinct list of the cipher ids associated with the organization member
    #[serde(rename = "cipherIds", skip_serializing_if = "Option::is_none")]
    pub cipher_ids: Option<Vec<String>>,
}

impl MemberCipherDetailsResponseModel {
    pub fn new() -> MemberCipherDetailsResponseModel {
        MemberCipherDetailsResponseModel {
            user_guid: None,
            user_name: None,
            email: None,
            uses_key_connector: None,
            cipher_ids: None,
        }
    }
}
