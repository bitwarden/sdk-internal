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
/// Every decision carries a [`verdict`](Self::verdict), an optional [`comment`](Self::comment), and
/// the time it was [`decided_at`](Self::decided_at). [`decider`](Self::decider) distinguishes an
/// automatic (access-rule) decision from a human one and, for a human, carries the approver's
/// identity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
            ApiDeciderKind::Automatic => AccessDecider::Automatic,
            ApiDeciderKind::Human => AccessDecider::Human(AccessApprover {
                id: response.id.map(UserId::new),
                name: response.name,
                email: response.email,
            }),
            ApiDeciderKind::__Unknown(_) => return Err(LeasingError::UnrecognizedDeciderKind),
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
            decider_kind: Some(DeciderKind::__Unknown(99)),
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
}
