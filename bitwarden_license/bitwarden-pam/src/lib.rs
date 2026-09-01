#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

use bitwarden_uuid::uuid_newtype;

mod access_requests;
mod access_rules;
mod approvals;
mod error;
mod leases;
mod pam_client;
mod rotation;

uuid_newtype!(pub AccessLeaseId);
uuid_newtype!(pub AccessRequestId);
uuid_newtype!(pub AccessRuleId);
uuid_newtype!(pub AccessConnectorId);
uuid_newtype!(pub RotationAttemptId);
uuid_newtype!(pub RotationConfigId);
uuid_newtype!(pub RotationJobId);
uuid_newtype!(pub TargetSystemId);

pub use access_requests::{
    AccessApprovalMode, AccessApprover, AccessBadgeState, AccessDecider, AccessDecisionVerdict,
    AccessPreCheckView, AccessRequestCreateRequest, AccessRequestDecisionView, AccessRequestError,
    AccessRequestResultView, AccessRequestStatus, AccessRequestSummaryView, AccessRequestView,
    AccessRequestWindowError, AccessRequestsClient, CipherAccessStateView,
    DEFAULT_REQUEST_ACCESS_DURATION_SECONDS, MAX_REQUEST_ACCESS_WINDOW_SECONDS,
    default_request_access_duration_seconds, max_request_access_window_seconds,
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
pub use rotation::{
    AccessConnector, AccessConnectorDetail, AccessConnectorRegistrationResponse,
    AccessConnectorStatus, AccessConnectorsClient, ConnectorToken, ConnectorTokenInvalidError,
    PasswordPolicy, QuartzSchedulePreset, RotationAttempt, RotationAttemptStatus, RotationClient,
    RotationConfig, RotationConfigActions, RotationConfigCreateRequest, RotationConfigDetail,
    RotationConfigUpdateRequest, RotationConfigsClient, RotationError, RotationJob,
    RotationJobStatus, RotationScheduleClient, RotationSource, RotationSyncState,
    RotationValidationError, SessionTerminationOutcome, TargetSystem, TargetSystemCreateRequest,
    TargetSystemKind, TargetSystemMethod, TargetSystemStatus, TargetSystemUpdateRequest,
    TargetSystemsClient, is_likely_quartz_cron, preset_for_cron, rotation_config_actions,
};
