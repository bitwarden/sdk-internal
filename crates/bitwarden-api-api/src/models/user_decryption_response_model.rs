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
pub struct UserDecryptionResponseModel {
    #[serde(
        rename = "masterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_password_unlock: Option<Box<models::MasterPasswordUnlockResponseModel>>,
}

impl UserDecryptionResponseModel {
    pub fn new() -> UserDecryptionResponseModel {
        UserDecryptionResponseModel {
            master_password_unlock: None,
        }
    }
}
