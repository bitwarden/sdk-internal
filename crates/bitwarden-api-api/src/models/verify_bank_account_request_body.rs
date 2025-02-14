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
pub struct VerifyBankAccountRequestBody {
    #[serde(rename = "descriptorCode")]
    pub descriptor_code: String,
}

impl VerifyBankAccountRequestBody {
    pub fn new(descriptor_code: String) -> VerifyBankAccountRequestBody {
        VerifyBankAccountRequestBody { descriptor_code }
    }
}
