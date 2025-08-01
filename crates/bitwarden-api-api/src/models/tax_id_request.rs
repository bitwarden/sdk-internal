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
pub struct TaxIdRequest {
    #[serde(rename = "code")]
    pub code: String,
    #[serde(rename = "value")]
    pub value: String,
}

impl TaxIdRequest {
    pub fn new(code: String, value: String) -> TaxIdRequest {
        TaxIdRequest { code, value }
    }
}
