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
pub struct PreviewTaxAmountForOrganizationTrialRequestBody {
    #[serde(rename = "planType")]
    pub plan_type: models::PlanType,
    #[serde(rename = "productType")]
    pub product_type: models::ProductType,
    #[serde(rename = "taxInformation")]
    pub tax_information: Box<models::TaxInformationDto>,
}

impl PreviewTaxAmountForOrganizationTrialRequestBody {
    pub fn new(
        plan_type: models::PlanType,
        product_type: models::ProductType,
        tax_information: models::TaxInformationDto,
    ) -> PreviewTaxAmountForOrganizationTrialRequestBody {
        PreviewTaxAmountForOrganizationTrialRequestBody {
            plan_type,
            product_type,
            tax_information: Box::new(tax_information),
        }
    }
}
