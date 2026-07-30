use bitwarden_api_api::models::{
    AccessDecisionVerdict as ApiAccessDecisionVerdict, AccessRequestDecisionResponseModel,
    AccessRequestDetailsResponseModel, AccessRequestStatus as ApiAccessRequestStatus,
    DeciderKind as ApiDeciderKind,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{OrganizationId, UserId, require};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{AccessLeaseId, AccessLeaseStatus, AccessRequestId, AccessRuleId, error::LeasingError};

/// The lifecycle state of an access request.
///
/// The automatic (no human approval) path moves `Pending -> Approved -> Activated`; the requester
/// activates the approved request to mint a lease. `Denied`, `Canceled`, and `Expired` are terminal
/// states in which no lease exists.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestStatus {
    /// Awaiting a decision (or, on the automatic path, awaiting the server's auto-approval).
    Pending,
    /// Approved but not yet activated; the requester may activate it to mint a lease.
    Approved,
    /// Activated - a lease has been minted from this request.
    Activated,
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
            ApiAccessRequestStatus::Activated => Self::Activated,
            ApiAccessRequestStatus::Denied => Self::Denied,
            ApiAccessRequestStatus::Canceled => Self::Canceled,
            ApiAccessRequestStatus::Expired => Self::Expired,
            ApiAccessRequestStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// What produced a decision on an access request.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum AccessDeciderKind {
    /// The decision was made automatically by the governing access rule; no human approval was
    /// required.
    Automatic,
    /// The decision was made by a human approver.
    Human,
    /// A decider kind value this SDK version does not recognize. Kept as a distinct variant so
    /// reading a request's decision log never fails on a newer server's decider kind.
    Unknown,
}

impl From<ApiDeciderKind> for AccessDeciderKind {
    fn from(kind: ApiDeciderKind) -> Self {
        match kind {
            ApiDeciderKind::Automatic => Self::Automatic,
            ApiDeciderKind::Human => Self::Human,
            ApiDeciderKind::__Unknown(_) => Self::Unknown,
        }
    }
}

/// An approver's verdict on an access request decision.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
/// For an [`Automatic`](AccessDeciderKind::Automatic) decision, `id`, `name`, and `email` are
/// `None`; for a [`Human`](AccessDeciderKind::Human) decision they carry the approver's identity,
/// denormalized by the server (`None` only when the user could not be resolved).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestDecisionView {
    /// Who made the decision.
    pub decider_kind: AccessDeciderKind,
    /// The human approver's user id; `None` for an automatic decision.
    pub id: Option<UserId>,
    /// The human approver's display name; `None` for an automatic decision, or when the user
    /// could not be resolved.
    pub name: Option<String>,
    /// The human approver's email; `None` for an automatic decision, or when the user could not
    /// be resolved.
    pub email: Option<String>,
    /// The optional note the approver left with the decision.
    pub comment: Option<String>,
    /// The decision's verdict.
    pub verdict: AccessDecisionVerdict,
    /// When the decision was recorded (UTC).
    pub decided_at: DateTime<Utc>,
}

impl TryFrom<AccessRequestDecisionResponseModel> for AccessRequestDecisionView {
    type Error = LeasingError;

    fn try_from(response: AccessRequestDecisionResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            decider_kind: AccessDeciderKind::from(require!(response.decider_kind)),
            id: response.id.map(UserId::new),
            name: response.name,
            email: response.email,
            comment: response.comment,
            verdict: AccessDecisionVerdict::from(require!(response.verdict)),
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{AccessLeaseStatus as ApiAccessLeaseStatus, DeciderKind};
    use uuid::Uuid;

    use super::*;

    fn human_decision() -> AccessRequestDecisionResponseModel {
        AccessRequestDecisionResponseModel {
            decider_kind: Some(DeciderKind::Human),
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
            decider_kind: Some(DeciderKind::Automatic),
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
            status: Some(ApiAccessRequestStatus::Activated),
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

        let human = &view.decisions[1];
        assert_eq!(human.decider_kind, AccessDeciderKind::Human);
        assert_eq!(human.name, Some("Ana Approver".to_string()));
        assert_eq!(human.email, Some("ana@example.com".to_string()));
        assert_eq!(human.comment, Some("Looks fine".to_string()));
        assert_eq!(human.verdict, AccessDecisionVerdict::Approve);
    }

    #[test]
    fn automatic_decision_has_no_approver_identity() {
        let view = AccessRequestDecisionView::try_from(automatic_decision()).unwrap();

        assert_eq!(view.decider_kind, AccessDeciderKind::Automatic);
        assert_eq!(view.id, None);
        assert_eq!(view.name, None);
        assert_eq!(view.email, None);
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
    fn unknown_decider_kind_and_verdict_map_to_unknown() {
        let response = AccessRequestDecisionResponseModel {
            decider_kind: Some(DeciderKind::__Unknown(99)),
            verdict: Some(ApiAccessDecisionVerdict::__Unknown(99)),
            ..human_decision()
        };

        let view = AccessRequestDecisionView::try_from(response).unwrap();

        assert_eq!(view.decider_kind, AccessDeciderKind::Unknown);
        assert_eq!(view.verdict, AccessDecisionVerdict::Unknown);
    }
}
