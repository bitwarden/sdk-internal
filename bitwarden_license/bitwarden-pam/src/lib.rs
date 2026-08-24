#![doc = include_str!("../README.md")]

use bitwarden_uuid::uuid_newtype;

mod access_requests;
mod access_rules;
mod approvals;
mod error;
mod leases;
mod pam_client;
mod problem;

uuid_newtype!(pub AccessLeaseId);
uuid_newtype!(pub AccessRequestId);
uuid_newtype!(pub AccessRuleId);

pub use access_requests::{
    AccessApprovalMode, AccessApprover, AccessBadgeState, AccessDecider, AccessDecisionVerdict,
    AccessPreCheckView, AccessRequestActivateError, AccessRequestCancelError,
    AccessRequestCreateRequest, AccessRequestDecisionView, AccessRequestResultView,
    AccessRequestStatus, AccessRequestSubmitError, AccessRequestSummaryView, AccessRequestView,
    AccessRequestWindowError, AccessRequestsClient, CipherAccessStateView,
    DEFAULT_REQUEST_ACCESS_DURATION_SECONDS, MAX_REQUEST_ACCESS_WINDOW_SECONDS,
    default_request_access_duration_seconds, max_request_access_window_seconds,
};
pub use access_rules::{
    AccessCondition, AccessRuleAddEditRequest, AccessRuleDecodeError, AccessRuleDeleteError,
    AccessRuleReadError, AccessRuleValidationError, AccessRuleView, AccessRuleWriteError,
    AccessRulesClient, is_valid_cidr,
};
pub use approvals::{AccessDecisionError, AccessDecisionRequest, ApprovalsClient};
pub use error::{PamDecodeError, PamReadError};
pub use leases::{
    AccessLeaseEndError, AccessLeaseExtendError, AccessLeaseExtensionRequest,
    AccessLeaseRevokeRequest, AccessLeaseStatus, AccessLeaseTermination, AccessLeaseView,
    LeasedCipherError, LeasesClient,
};
pub use pam_client::{PamClient, PamClientExt};
