#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

use bitwarden_uuid::uuid_newtype;

mod access_rules;
mod pam_client;

uuid_newtype!(pub AccessRuleId);

pub use access_rules::{
    AccessCondition, AccessRuleAddEditRequest, AccessRuleError, AccessRuleValidationError,
    AccessRuleView, AccessRulesClient, is_valid_cidr,
};
pub use pam_client::{PamClient, PamClientExt};
