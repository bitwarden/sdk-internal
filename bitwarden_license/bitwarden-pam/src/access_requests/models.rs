use bitwarden_api_api::models::{
    AccessRequestDetailsResponseModel, AccessRequestStatus as ApiAccessRequestStatus,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{OrganizationId, UserId, require};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{AccessRequestId, AccessRuleId, error::LeasingError};

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
        })
    }
}
