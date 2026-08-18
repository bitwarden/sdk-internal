#![doc = include_str!("../README.md")]

use bitwarden_uuid::uuid_newtype;

mod access_requests;
mod access_rules;
mod approvals;
mod error;
mod leases;
mod pam_client;

uuid_newtype!(pub AccessLeaseId);
uuid_newtype!(pub AccessRequestId);
uuid_newtype!(pub AccessRuleId);

pub use access_requests::{
    AccessApprovalMode, AccessApprover, AccessBadgeState, AccessDecider, AccessDecisionVerdict,
    AccessPreCheckView, AccessRequestCreateRequest, AccessRequestDecisionView, AccessRequestError,
    AccessRequestResultView, AccessRequestStatus, AccessRequestSummaryView, AccessRequestView,
    AccessRequestWindowError, AccessRequestsClient, CipherAccessStateView,
    MAX_REQUEST_ACCESS_WINDOW_SECONDS, max_request_access_window_seconds,
};
pub use access_rules::{
    AccessCondition, AccessRuleAddEditRequest, AccessRuleError, AccessRuleValidationError,
    AccessRuleView, AccessRulesClient, is_valid_cidr,
};
pub use approvals::{AccessDecisionRequest, ApprovalError, ApprovalsClient};
pub use error::PamDecodeError;
pub use leases::{
    AccessLeaseError, AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseStatus,
    AccessLeaseTermination, AccessLeaseView, LeasesClient,
};
pub use pam_client::{PamClient, PamClientExt};
