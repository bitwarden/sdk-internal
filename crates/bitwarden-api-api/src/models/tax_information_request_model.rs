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
pub struct TaxInformationRequestModel {
    #[serde(rename = "country")]
    pub country: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
    #[serde(rename = "taxId", skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
}

impl TaxInformationRequestModel {
    pub fn new(country: String, postal_code: String) -> TaxInformationRequestModel {
        TaxInformationRequestModel {
            country,
            postal_code,
            tax_id: None,
        }
    }
}
