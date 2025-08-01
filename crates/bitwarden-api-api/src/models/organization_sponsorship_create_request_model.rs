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
pub struct OrganizationSponsorshipCreateRequestModel {
    #[serde(rename = "planSponsorshipType")]
    pub plan_sponsorship_type: models::PlanSponsorshipType,
    #[serde(rename = "sponsoredEmail")]
    pub sponsored_email: String,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "isAdminInitiated", skip_serializing_if = "Option::is_none")]
    pub is_admin_initiated: Option<bool>,
    #[serde(rename = "notes", skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl OrganizationSponsorshipCreateRequestModel {
    pub fn new(
        plan_sponsorship_type: models::PlanSponsorshipType,
        sponsored_email: String,
    ) -> OrganizationSponsorshipCreateRequestModel {
        OrganizationSponsorshipCreateRequestModel {
            plan_sponsorship_type,
            sponsored_email,
            friendly_name: None,
            is_admin_initiated: None,
            notes: None,
        }
    }
}
