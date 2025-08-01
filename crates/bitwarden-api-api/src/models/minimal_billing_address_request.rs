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
pub struct MinimalBillingAddressRequest {
    #[serde(rename = "country")]
    pub country: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
}

impl MinimalBillingAddressRequest {
    pub fn new(country: String, postal_code: String) -> MinimalBillingAddressRequest {
        MinimalBillingAddressRequest {
            country,
            postal_code,
        }
    }
}
