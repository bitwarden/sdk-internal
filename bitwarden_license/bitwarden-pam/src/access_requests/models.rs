use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    AccessApprovalMode as ApiAccessApprovalMode, AccessDeciderKind as ApiAccessDeciderKind,
    AccessDecisionVerdict as ApiAccessDecisionVerdict, AccessPreCheckResponseModel,
    AccessRequestCreateRequestModel, AccessRequestDecisionResponseModel,
    AccessRequestDetailsResponseModel, AccessRequestResultResponseModel,
    AccessRequestStatus as ApiAccessRequestStatus, CipherAccessStateResponseModel,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{OrganizationId, UserId, require};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AccessLeaseId, AccessLeaseStatus, AccessRequestId, AccessRuleId, error::LeasingError,
    leases::AccessLeaseView,
};

/// The lifecycle state of an access request.
///
/// The automatic (no human approval) path moves `Pending -> Approved`; the requester activates the
/// approved request to mint a lease. Activation does not change the status — it is observed through
/// [`produced_lease_id`](AccessRequestView::produced_lease_id) and
/// [`produced_lease_status`](AccessRequestView::produced_lease_status). `Denied`, `Canceled`, and
/// `Expired` are terminal states in which no lease exists.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestStatus {
    /// Awaiting a decision (or, on the automatic path, awaiting the server's auto-approval).
    Pending,
    /// Approved; the requester may activate it to mint a lease.
    Approved,
    /// Denied by an approver; terminal.
    Denied,
    /// Cancelled by the requester before resolution; terminal.
    Canceled,
    /// Approved but lapsed before the requester activated it; terminal.
    Expired,
    /// A status value this SDK version does not recognize. Kept as a distinct variant so listing
    /// requests never fails on a newer server's status.
    Unknown,
}

impl From<ApiAccessRequestStatus> for AccessRequestStatus {
    fn from(status: ApiAccessRequestStatus) -> Self {
        match status {
            ApiAccessRequestStatus::Pending => Self::Pending,
            ApiAccessRequestStatus::Approved => Self::Approved,
            ApiAccessRequestStatus::Denied => Self::Denied,
            ApiAccessRequestStatus::Cancelled => Self::Canceled,
            ApiAccessRequestStatus::Expired => Self::Expired,
            ApiAccessRequestStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// An approver's verdict on an access request decision.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "snake_case")]
pub enum AccessDecisionVerdict {
    /// The request was denied.
    Deny,
    /// The request was approved.
    Approve,
    /// A verdict value this SDK version does not recognize. Kept as a distinct variant so reading
    /// a request's decision log never fails on a newer server's verdict.
    Unknown,
}

impl From<ApiAccessDecisionVerdict> for AccessDecisionVerdict {
    fn from(verdict: ApiAccessDecisionVerdict) -> Self {
        match verdict {
            ApiAccessDecisionVerdict::Deny => Self::Deny,
            ApiAccessDecisionVerdict::Approve => Self::Approve,
            ApiAccessDecisionVerdict::__Unknown(_) => Self::Unknown,
        }
    }
}

/// A single decision recorded on an access request's decision log.
///
/// Every decision carries a [`verdict`](Self::verdict), an optional [`comment`](Self::comment), and
/// the time it was [`decided_at`](Self::decided_at). [`decider`](Self::decider) distinguishes an
/// automatic (access-rule) decision from a human one and, for a human, carries the approver's
/// identity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestDecisionView {
    /// Who made the decision.
    pub decider: AccessDecider,
    /// The decision's verdict.
    pub verdict: AccessDecisionVerdict,
    /// The optional note recorded with the decision.
    pub comment: Option<String>,
    /// When the decision was recorded (UTC).
    pub decided_at: DateTime<Utc>,
}

/// Who made a decision on an access request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub enum AccessDecider {
    /// The decision was made automatically by the governing access rule; no human approval was
    /// required.
    Automatic,
    /// The decision was made by a human approver, whose identity is denormalized by the server.
    Human(AccessApprover),
}

/// The identity of a human approver, denormalized by the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessApprover {
    /// The approver's user id; `None` when the server omitted it.
    pub id: Option<UserId>,
    /// The approver's display name; `None` when the user could not be resolved.
    pub name: Option<String>,
    /// The approver's email; `None` when the user could not be resolved.
    pub email: Option<String>,
}

impl TryFrom<AccessRequestDecisionResponseModel> for AccessRequestDecisionView {
    type Error = LeasingError;

    fn try_from(response: AccessRequestDecisionResponseModel) -> Result<Self, Self::Error> {
        let decider = match require!(response.decider_kind) {
            ApiAccessDeciderKind::Automatic => AccessDecider::Automatic,
            ApiAccessDeciderKind::Human => AccessDecider::Human(AccessApprover {
                id: response.id.map(UserId::new),
                name: response.name,
                email: response.email,
            }),
            ApiAccessDeciderKind::__Unknown(_) => {
                return Err(LeasingError::UnrecognizedDeciderKind);
            }
        };

        Ok(Self {
            decider,
            verdict: AccessDecisionVerdict::from(require!(response.verdict)),
            comment: response.comment,
            decided_at: require!(response.decided_at).parse()?,
        })
    }
}

/// A decrypted view of an access request, as its requester sees it.
///
/// An access request is a member's ask to open a PAM-gated cipher. Once approved, the requester
/// [`activate`](crate::AccessRequestsClient::activate)s it to mint an
/// [`AccessLease`](crate::AccessLeaseView).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestView {
    /// The request's unique identifier.
    pub id: AccessRequestId,
    /// The cipher access was requested for.
    pub cipher_id: CipherId,
    /// The collection the cipher belongs to, through which the request is governed.
    pub collection_id: CollectionId,
    /// The organization that owns the cipher. None when the server omits it.
    pub organization_id: Option<OrganizationId>,
    /// The member who opened the request.
    pub requester_id: UserId,
    /// The access rule pinned to the request at submit time. None for requests created before rule
    /// pinning existed.
    pub rule_id: Option<AccessRuleId>,
    /// The request's lifecycle state.
    pub status: AccessRequestStatus,
    /// The start of the activation window resolved at submit (UTC) - the earliest the request may
    /// be promoted to a lease.
    pub lease_not_before: DateTime<Utc>,
    /// The end of the activation window resolved at submit (UTC).
    pub lease_not_after: DateTime<Utc>,
    /// The optional justification the requester supplied when opening the request.
    pub reason: Option<String>,
    /// When the request was opened (UTC).
    pub submitted_at: DateTime<Utc>,
    /// When the request was approved, denied, or cancelled (UTC); None while pending.
    pub resolved_at: Option<DateTime<Utc>>,
    /// The request's decision log, oldest first. Empty only while pending.
    pub decisions: Vec<AccessRequestDecisionView>,
    /// The lease produced once this (approved) request was activated. None until activation.
    pub produced_lease_id: Option<AccessLeaseId>,
    /// The status of the produced lease at the time this view was fetched. None until activation.
    pub produced_lease_status: Option<AccessLeaseStatus>,
    /// The parent lease this request extends, if it is an extension request. None otherwise.
    pub extension_of_lease_id: Option<AccessLeaseId>,
    /// The requester's display name, denormalized by the server. None only when the user could
    /// not be resolved.
    pub requester_name: Option<String>,
    /// The requester's email, denormalized by the server. None only when the user could not be
    /// resolved.
    pub requester_email: Option<String>,
}

impl TryFrom<AccessRequestDetailsResponseModel> for AccessRequestView {
    type Error = LeasingError;

    fn try_from(response: AccessRequestDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: AccessRequestId::new(require!(response.id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            collection_id: CollectionId::new(require!(response.collection_id)),
            organization_id: response.organization_id.map(OrganizationId::new),
            requester_id: UserId::new(require!(response.requester_id)),
            rule_id: response.rule_id.map(AccessRuleId::new),
            status: AccessRequestStatus::from(require!(response.status)),
            lease_not_before: require!(response.lease_not_before).parse()?,
            lease_not_after: require!(response.lease_not_after).parse()?,
            reason: response.reason,
            submitted_at: require!(response.submitted_at).parse()?,
            resolved_at: response.resolved_at.map(|d| d.parse()).transpose()?,
            decisions: response
                .decisions
                .unwrap_or_default()
                .into_iter()
                .map(AccessRequestDecisionView::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            produced_lease_id: response.produced_lease_id.map(AccessLeaseId::new),
            produced_lease_status: response.produced_lease_status.map(AccessLeaseStatus::from),
            extension_of_lease_id: response.extension_of_lease_id.map(AccessLeaseId::new),
            requester_name: response.requester_name,
            requester_email: response.requester_email,
        })
    }
}

/// The approval path a lease request will take, surfaced by
/// [`pre_check`](crate::AccessRequestsClient::pre_check) so the client can present the right
/// workflow before the requester commits.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "snake_case")]
pub enum AccessApprovalMode {
    /// A request would be approved immediately - the client should let the requester pick a
    /// duration.
    Automatic,
    /// A request would need an approver - the client should let the requester pick a window and
    /// justify it.
    Human,
    /// An approval mode value this SDK version does not recognize.
    Unknown,
}

impl From<ApiAccessApprovalMode> for AccessApprovalMode {
    fn from(mode: ApiAccessApprovalMode) -> Self {
        match mode {
            ApiAccessApprovalMode::Automatic => Self::Automatic,
            ApiAccessApprovalMode::Human => Self::Human,
            ApiAccessApprovalMode::__Unknown(_) => Self::Unknown,
        }
    }
}

/// The resolved approval outcome for a cipher, read without submitting a request.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessPreCheckView {
    /// The cipher this pre-check was resolved for.
    pub cipher_id: CipherId,
    /// The approval path a request for this cipher would take.
    pub approval_mode: AccessApprovalMode,
    /// True when the caller already holds an active lease: reveal the credential, no request
    /// needed.
    pub has_active_lease: bool,
}

impl TryFrom<AccessPreCheckResponseModel> for AccessPreCheckView {
    type Error = LeasingError;

    fn try_from(response: AccessPreCheckResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            cipher_id: CipherId::new(require!(response.cipher_id)),
            approval_mode: AccessApprovalMode::from(require!(response.approval_mode)),
            has_active_lease: require!(response.has_active_lease),
        })
    }
}

/// A decrypted view of an access request as its requester sees it right after submitting it.
///
/// A lighter sibling of [`AccessRequestView`]: the create response doesn't carry a decision log,
/// pinned rule, produced-lease linkage, or denormalized requester identity, since none of those
/// exist yet for a request that was just opened.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestSummaryView {
    /// The request's unique identifier.
    pub id: AccessRequestId,
    /// The cipher access was requested for.
    pub cipher_id: CipherId,
    /// The collection the cipher belongs to, through which the request is governed.
    pub collection_id: CollectionId,
    /// The organization that owns the cipher. None when the server omits it.
    pub organization_id: Option<OrganizationId>,
    /// The request's lifecycle state.
    pub status: AccessRequestStatus,
    /// The start of the activation window resolved at submit (UTC).
    pub lease_not_before: DateTime<Utc>,
    /// The end of the activation window resolved at submit (UTC).
    pub lease_not_after: DateTime<Utc>,
    /// The optional justification the requester supplied when opening the request.
    pub reason: Option<String>,
    /// When the request was opened (UTC).
    pub submitted_at: DateTime<Utc>,
}

impl TryFrom<AccessRequestDetailsResponseModel> for AccessRequestSummaryView {
    type Error = LeasingError;

    fn try_from(response: AccessRequestDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: AccessRequestId::new(require!(response.id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            collection_id: CollectionId::new(require!(response.collection_id)),
            organization_id: response.organization_id.map(OrganizationId::new),
            status: AccessRequestStatus::from(require!(response.status)),
            lease_not_before: require!(response.lease_not_before).parse()?,
            lease_not_after: require!(response.lease_not_after).parse()?,
            reason: response.reason,
            submitted_at: require!(response.submitted_at).parse()?,
        })
    }
}

/// The result of submitting a cipher-lease request.
///
/// No lease is minted at submit on either path - the requester
/// [`activate`](crate::AccessRequestsClient::activate)s the request to start the lease.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestResultView {
    /// [`Automatic`](AccessApprovalMode::Automatic) when [`request`](Self::request) was approved
    /// on submit and is ready to activate, [`Human`](AccessApprovalMode::Human) when it is
    /// pending an approver.
    pub approval_mode: AccessApprovalMode,
    /// The request that was just submitted.
    pub request: AccessRequestSummaryView,
}

impl TryFrom<AccessRequestResultResponseModel> for AccessRequestResultView {
    type Error = LeasingError;

    fn try_from(response: AccessRequestResultResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            approval_mode: AccessApprovalMode::from(require!(response.approval_mode)),
            request: AccessRequestSummaryView::try_from(*require!(response.request))?,
        })
    }
}

/// A single-snapshot read of the caller's access state for one cipher, powering the cipher-view
/// banner and the vault-row badge.
///
/// At most one of [`active_lease`](Self::active_lease), [`pending_request`](Self::pending_request),
/// and [`approved_request`](Self::approved_request) is meaningfully "next": an active lease
/// authorizes access, a pending request awaits a decision, and an approved request awaits
/// activation by the caller.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct CipherAccessStateView {
    /// The cipher this state was resolved for.
    pub cipher_id: CipherId,
    /// The caller's active lease over this cipher, if any.
    pub active_lease: Option<AccessLeaseView>,
    /// The caller's request awaiting a decision on this cipher, if any.
    pub pending_request: Option<AccessRequestView>,
    /// The caller's approved-but-not-yet-activated request on this cipher, if any. Lapsed
    /// approvals are never surfaced here.
    pub approved_request: Option<AccessRequestView>,
    /// Whether the active lease can still be extended.
    pub extensions_allowed: bool,
    /// The longest a single extension of the active lease may run, in seconds; None when there is
    /// no cap or no active lease.
    pub max_extension_duration_seconds: Option<i32>,
}

impl TryFrom<CipherAccessStateResponseModel> for CipherAccessStateView {
    type Error = LeasingError;

    fn try_from(response: CipherAccessStateResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            cipher_id: CipherId::new(require!(response.cipher_id)),
            active_lease: response
                .active_lease
                .map(|lease| AccessLeaseView::try_from(*lease))
                .transpose()?,
            pending_request: response
                .pending_request
                .map(|request| AccessRequestView::try_from(*request))
                .transpose()?,
            approved_request: response
                .approved_request
                .map(|request| AccessRequestView::try_from(*request))
                .transpose()?,
            extensions_allowed: require!(response.extensions_allowed),
            max_extension_duration_seconds: response.max_extension_duration_seconds,
        })
    }
}

/// Request to lease a cipher.
///
/// Supply [`duration_seconds`](Self::duration_seconds) for the automatic path, or
/// [`start`](Self::start)/[`end`](Self::end) + [`reason`](Self::reason) for the human path. Run a
/// [`pre_check`](crate::AccessRequestsClient::pre_check) first to know which shape the server
/// expects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestCreateRequest {
    /// How long the automatic path's lease should run, in seconds. None on the human path.
    pub duration_seconds: Option<NonZeroU32>,
    /// The start of the requested window (UTC). Required on the human path.
    pub start: Option<DateTime<Utc>>,
    /// The end of the requested window (UTC). Required on the human path.
    pub end: Option<DateTime<Utc>>,
    /// The justification recorded with the request. Required on the human path.
    pub reason: Option<String>,
}

impl From<AccessRequestCreateRequest> for AccessRequestCreateRequestModel {
    fn from(request: AccessRequestCreateRequest) -> Self {
        Self {
            duration_seconds: request.duration_seconds.map(|d| d.get() as i32),
            start: request.start.map(|d| d.to_rfc3339()),
            end: request.end.map(|d| d.to_rfc3339()),
            reason: request.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        AccessDeciderKind, AccessLeaseResponseModel, AccessLeaseStatus as ApiAccessLeaseStatus,
    };
    use uuid::{Uuid, uuid};

    use super::*;

    fn human_decision() -> AccessRequestDecisionResponseModel {
        AccessRequestDecisionResponseModel {
            decider_kind: Some(AccessDeciderKind::Human),
            id: Some(Uuid::new_v4()),
            name: Some("Ana Approver".to_string()),
            email: Some("ana@example.com".to_string()),
            comment: Some("Looks fine".to_string()),
            verdict: Some(ApiAccessDecisionVerdict::Approve),
            decided_at: Some("2025-01-01T00:30:00Z".to_string()),
        }
    }

    fn automatic_decision() -> AccessRequestDecisionResponseModel {
        AccessRequestDecisionResponseModel {
            decider_kind: Some(AccessDeciderKind::Automatic),
            id: None,
            name: None,
            email: None,
            comment: None,
            verdict: Some(ApiAccessDecisionVerdict::Approve),
            decided_at: Some("2025-01-01T00:00:05Z".to_string()),
        }
    }

    fn full_response() -> AccessRequestDetailsResponseModel {
        AccessRequestDetailsResponseModel {
            id: Some(Uuid::new_v4()),
            cipher_id: Some(Uuid::new_v4()),
            collection_id: Some(Uuid::new_v4()),
            organization_id: Some(Uuid::new_v4()),
            requester_id: Some(Uuid::new_v4()),
            rule_id: Some(Uuid::new_v4()),
            status: Some(ApiAccessRequestStatus::Approved),
            lease_not_before: Some("2025-01-01T00:00:00Z".to_string()),
            lease_not_after: Some("2025-01-01T01:00:00Z".to_string()),
            reason: Some("Need to fix an incident".to_string()),
            submitted_at: Some("2025-01-01T00:00:00Z".to_string()),
            resolved_at: Some("2025-01-01T00:30:00Z".to_string()),
            decisions: Some(vec![automatic_decision(), human_decision()]),
            produced_lease_id: Some(Uuid::new_v4()),
            produced_lease_status: Some(ApiAccessLeaseStatus::Active),
            extension_of_lease_id: Some(Uuid::new_v4()),
            requester_name: Some("Rea Quester".to_string()),
            requester_email: Some("rea@example.com".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn full_response_converts_decisions_and_lease_linkage() {
        let response = full_response();
        let expected_produced_lease_id = response.produced_lease_id.unwrap();
        let expected_extension_of_lease_id = response.extension_of_lease_id.unwrap();

        let view = AccessRequestView::try_from(response).unwrap();

        assert_eq!(view.decisions.len(), 2);
        assert_eq!(
            view.produced_lease_id,
            Some(AccessLeaseId::new(expected_produced_lease_id))
        );
        assert_eq!(view.produced_lease_status, Some(AccessLeaseStatus::Active));
        assert_eq!(
            view.extension_of_lease_id,
            Some(AccessLeaseId::new(expected_extension_of_lease_id))
        );
        assert_eq!(view.requester_name, Some("Rea Quester".to_string()));
        assert_eq!(view.requester_email, Some("rea@example.com".to_string()));

        assert!(matches!(
            view.decisions[0].decider,
            AccessDecider::Automatic
        ));

        let decision = &view.decisions[1];
        let AccessDecider::Human(approver) = &decision.decider else {
            panic!("expected a human decision, got {:?}", decision.decider);
        };
        assert_eq!(approver.name.as_deref(), Some("Ana Approver"));
        assert_eq!(approver.email.as_deref(), Some("ana@example.com"));
        assert_eq!(decision.comment.as_deref(), Some("Looks fine"));
        assert_eq!(decision.verdict, AccessDecisionVerdict::Approve);
    }

    #[test]
    fn automatic_decision_has_no_approver_identity() {
        let view = AccessRequestDecisionView::try_from(automatic_decision()).unwrap();

        assert!(matches!(view.decider, AccessDecider::Automatic));
    }

    #[test]
    fn missing_decisions_becomes_empty_vec() {
        let response = AccessRequestDetailsResponseModel {
            decisions: None,
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert_eq!(view.decisions, Vec::new());
    }

    #[test]
    fn unknown_decider_kind_is_rejected() {
        let response = AccessRequestDecisionResponseModel {
            decider_kind: Some(AccessDeciderKind::__Unknown(99)),
            ..human_decision()
        };

        assert!(AccessRequestDecisionView::try_from(response).is_err());
    }

    #[test]
    fn unknown_verdict_maps_to_unknown() {
        let response = AccessRequestDecisionResponseModel {
            verdict: Some(ApiAccessDecisionVerdict::__Unknown(99)),
            ..human_decision()
        };

        let view = AccessRequestDecisionView::try_from(response).unwrap();

        assert_eq!(view.verdict, AccessDecisionVerdict::Unknown);
    }

    #[test]
    fn human_decision_serializes_with_nested_approver() {
        let view = AccessRequestDecisionView::try_from(human_decision()).unwrap();

        let json = serde_json::to_value(&view).unwrap();

        assert_eq!(json["decider"]["human"]["name"], "Ana Approver");
        assert_eq!(json["decider"]["human"]["email"], "ana@example.com");
        assert_eq!(json["verdict"], "approve");
        assert!(json.get("decidedAt").is_some());
    }

    #[test]
    fn automatic_decision_serializes_without_approver() {
        let view = AccessRequestDecisionView::try_from(automatic_decision()).unwrap();

        let json = serde_json::to_value(&view).unwrap();

        assert_eq!(json["decider"], "automatic");
        assert_eq!(json["verdict"], "approve");
    }

    fn request_id() -> AccessRequestId {
        AccessRequestId::new(uuid!("44444444-4444-4444-4444-444444444444"))
    }

    fn cipher_id() -> uuid::Uuid {
        uuid!("55555555-5555-5555-5555-555555555555")
    }

    #[test]
    fn pre_check_view_converts() {
        let response = AccessPreCheckResponseModel {
            cipher_id: Some(cipher_id()),
            approval_mode: Some(ApiAccessApprovalMode::Automatic),
            has_active_lease: Some(true),
            ..Default::default()
        };

        let view = AccessPreCheckView::try_from(response).unwrap();

        assert_eq!(view.cipher_id, CipherId::new(cipher_id()));
        assert_eq!(view.approval_mode, AccessApprovalMode::Automatic);
        assert!(view.has_active_lease);
    }

    #[test]
    fn pre_check_view_maps_unknown_approval_mode() {
        let response = AccessPreCheckResponseModel {
            approval_mode: Some(ApiAccessApprovalMode::__Unknown(99)),
            ..AccessPreCheckResponseModel {
                cipher_id: Some(cipher_id()),
                has_active_lease: Some(false),
                ..Default::default()
            }
        };

        let view = AccessPreCheckView::try_from(response).unwrap();

        assert_eq!(view.approval_mode, AccessApprovalMode::Unknown);
    }

    fn sample_created_request() -> AccessRequestDetailsResponseModel {
        AccessRequestDetailsResponseModel {
            id: Some(request_id().into()),
            cipher_id: Some(cipher_id()),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            organization_id: Some(uuid!("77777777-7777-7777-7777-777777777777")),
            status: Some(ApiAccessRequestStatus::Pending),
            lease_not_before: Some("2025-01-01T00:00:00Z".to_string()),
            lease_not_after: Some("2025-01-01T01:00:00Z".to_string()),
            reason: Some("Need to fix an incident".to_string()),
            submitted_at: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn access_request_summary_view_converts() {
        let view = AccessRequestSummaryView::try_from(sample_created_request()).unwrap();

        assert_eq!(view.id, request_id());
        assert_eq!(view.cipher_id, CipherId::new(cipher_id()));
        assert_eq!(view.status, AccessRequestStatus::Pending);
        assert_eq!(view.reason, Some("Need to fix an incident".to_string()));
    }

    #[test]
    fn access_request_result_view_converts() {
        let response = AccessRequestResultResponseModel {
            approval_mode: Some(ApiAccessApprovalMode::Human),
            request: Some(Box::new(sample_created_request())),
            ..Default::default()
        };

        let view = AccessRequestResultView::try_from(response).unwrap();

        assert_eq!(view.approval_mode, AccessApprovalMode::Human);
        assert_eq!(view.request.id, request_id());
    }

    #[test]
    fn cipher_access_state_view_converts_when_nothing_active() {
        let response = CipherAccessStateResponseModel {
            cipher_id: Some(cipher_id()),
            active_lease: None,
            pending_request: None,
            approved_request: None,
            extensions_allowed: Some(false),
            max_extension_duration_seconds: None,
            ..Default::default()
        };

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(view.cipher_id, CipherId::new(cipher_id()));
        assert_eq!(view.active_lease, None);
        assert_eq!(view.pending_request, None);
        assert_eq!(view.approved_request, None);
        assert!(!view.extensions_allowed);
        assert_eq!(view.max_extension_duration_seconds, None);
    }

    #[test]
    fn cipher_access_state_view_converts_when_all_branches_populated() {
        let response = CipherAccessStateResponseModel {
            cipher_id: Some(cipher_id()),
            active_lease: Some(Box::new(AccessLeaseResponseModel {
                id: Some(uuid!("33333333-3333-3333-3333-333333333333")),
                request_id: Some(request_id().into()),
                cipher_id: Some(cipher_id()),
                collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
                requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
                status: Some(ApiAccessLeaseStatus::Active),
                not_before: Some("2025-01-01T00:00:00Z".to_string()),
                not_after: Some("2025-01-01T01:00:00Z".to_string()),
                ..Default::default()
            })),
            pending_request: Some(Box::new(full_response())),
            approved_request: Some(Box::new(full_response())),
            extensions_allowed: Some(true),
            max_extension_duration_seconds: Some(3600),
            ..Default::default()
        };

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert!(view.active_lease.is_some());
        assert!(view.pending_request.is_some());
        assert!(view.approved_request.is_some());
        assert!(view.extensions_allowed);
        assert_eq!(view.max_extension_duration_seconds, Some(3600));
    }

    #[test]
    fn access_request_create_request_converts_to_model() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(3600),
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2025-01-01T01:00:00Z".parse().unwrap()),
            reason: Some("Need access".to_string()),
        };

        let model = AccessRequestCreateRequestModel::from(request);

        assert_eq!(model.duration_seconds, Some(3600));
        assert_eq!(model.start, Some("2025-01-01T00:00:00+00:00".to_string()));
        assert_eq!(model.end, Some("2025-01-01T01:00:00+00:00".to_string()));
        assert_eq!(model.reason, Some("Need access".to_string()));
    }
}
