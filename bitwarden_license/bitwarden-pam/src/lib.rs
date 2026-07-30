#![doc = include_str!("../README.md")]

use bitwarden_uuid::uuid_newtype;

mod access_requests;
mod access_rules;
mod error;
mod leases;
mod pam_client;

uuid_newtype!(pub AccessLeaseId);
uuid_newtype!(pub AccessRequestId);
uuid_newtype!(pub AccessRuleId);

pub use access_requests::{
    AccessDeciderKind, AccessDecisionVerdict, AccessRequestDecisionView, AccessRequestStatus,
    AccessRequestView, AccessRequestsClient,
};
pub use access_rules::{
    AccessCondition, AccessRuleAddEditRequest, AccessRuleError, AccessRuleValidationError,
    AccessRuleView, AccessRulesClient, is_valid_cidr,
};
pub use error::LeasingError;
pub use leases::{
    AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseStatus, AccessLeaseView,
    LeasesClient,
};
pub use pam_client::{PamClient, PamClientExt};
