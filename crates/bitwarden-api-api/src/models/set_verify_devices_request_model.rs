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
pub struct SetVerifyDevicesRequestModel {
    #[serde(rename = "masterPasswordHash", skip_serializing_if = "Option::is_none")]
    pub master_password_hash: Option<String>,
    #[serde(rename = "otp", skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
    #[serde(
        rename = "authRequestAccessCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_request_access_code: Option<String>,
    #[serde(rename = "secret", skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(rename = "verifyDevices")]
    pub verify_devices: bool,
}

impl SetVerifyDevicesRequestModel {
    pub fn new(verify_devices: bool) -> SetVerifyDevicesRequestModel {
        SetVerifyDevicesRequestModel {
            master_password_hash: None,
            otp: None,
            auth_request_access_code: None,
            secret: None,
            verify_devices,
        }
    }
}
