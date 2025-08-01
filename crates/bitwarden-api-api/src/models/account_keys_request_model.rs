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
pub struct AccountKeysRequestModel {
    #[serde(rename = "userKeyEncryptedAccountPrivateKey")]
    pub user_key_encrypted_account_private_key: Option<String>,
    #[serde(rename = "accountPublicKey")]
    pub account_public_key: Option<String>,
}

impl AccountKeysRequestModel {
    pub fn new(
        user_key_encrypted_account_private_key: Option<String>,
        account_public_key: Option<String>,
    ) -> AccountKeysRequestModel {
        AccountKeysRequestModel {
            user_key_encrypted_account_private_key,
            account_public_key,
        }
    }
}
