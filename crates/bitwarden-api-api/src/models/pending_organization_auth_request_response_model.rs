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
pub struct PendingOrganizationAuthRequestResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<uuid::Uuid>,
    #[serde(rename = "organizationUserId", skip_serializing_if = "Option::is_none")]
    pub organization_user_id: Option<uuid::Uuid>,
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(
        rename = "requestDeviceIdentifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_device_identifier: Option<String>,
    #[serde(rename = "requestDeviceType", skip_serializing_if = "Option::is_none")]
    pub request_device_type: Option<String>,
    #[serde(rename = "requestIpAddress", skip_serializing_if = "Option::is_none")]
    pub request_ip_address: Option<String>,
    #[serde(rename = "requestCountryName", skip_serializing_if = "Option::is_none")]
    pub request_country_name: Option<String>,
    #[serde(rename = "creationDate", skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

impl PendingOrganizationAuthRequestResponseModel {
    pub fn new() -> PendingOrganizationAuthRequestResponseModel {
        PendingOrganizationAuthRequestResponseModel {
            object: None,
            id: None,
            user_id: None,
            organization_user_id: None,
            email: None,
            public_key: None,
            request_device_identifier: None,
            request_device_type: None,
            request_ip_address: None,
            request_country_name: None,
            creation_date: None,
        }
    }
}
