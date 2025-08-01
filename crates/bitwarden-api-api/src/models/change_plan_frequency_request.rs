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
pub struct ChangePlanFrequencyRequest {
    #[serde(rename = "newPlanType")]
    pub new_plan_type: models::PlanType,
}

impl ChangePlanFrequencyRequest {
    pub fn new(new_plan_type: models::PlanType) -> ChangePlanFrequencyRequest {
        ChangePlanFrequencyRequest { new_plan_type }
    }
}
