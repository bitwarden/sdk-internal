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
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::validate::{
    AccessRequestWindowError, DEFAULT_REQUEST_ACCESS_DURATION_SECONDS,
    MAX_REQUEST_ACCESS_WINDOW_SECONDS,
};
use crate::{
    AccessLeaseId, AccessLeaseStatus, AccessRequestId, AccessRuleId, error::PamDecodeError,
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
    /// The window lapsed with nothing to show for it: either nobody answered an open request, or
    /// an approval was never activated. The two origins share this one value; distinguish them
    /// via [`decisions`](AccessRequestView::decisions) (empty = unanswered, contains an approval
    /// = unactivated). An expired request's end time is
    /// [`lease_not_after`](AccessRequestView::lease_not_after); terminal.
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
    type Error = PamDecodeError;

    fn try_from(response: AccessRequestDecisionResponseModel) -> Result<Self, Self::Error> {
        let decider = match require!(response.decider_kind) {
            ApiAccessDeciderKind::Automatic => AccessDecider::Automatic,
            ApiAccessDeciderKind::Human => AccessDecider::Human(AccessApprover {
                id: response.id.map(UserId::new),
                name: response.name,
                email: response.email,
            }),
            ApiAccessDeciderKind::__Unknown(_) => {
                return Err(PamDecodeError::UnrecognizedDeciderKind);
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
    /// When a party approved, denied, or cancelled the request (UTC); None while pending - and
    /// None for expired requests, which nobody resolved (their end time is
    /// [`lease_not_after`](Self::lease_not_after)).
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
    /// True when this request is approved but has not been activated into a lease yet, so the
    /// requester still has something to do with it.
    ///
    /// Activation is not a status: an activated request stays
    /// [`Approved`](AccessRequestStatus::Approved) and is recognised by the
    /// [`produced_lease_id`](Self::produced_lease_id) it minted. Every client needs this
    /// distinction - to badge a navigation counter, to decide whether to offer a Start action, to
    /// keep an already-started grant out of a pending list - and deriving it from two fields is
    /// exactly the kind of rule each of them would otherwise get subtly wrong.
    ///
    /// Deliberately says nothing about whether the activation window is still open. That depends
    /// on wall-clock time at the moment the client renders, not at the moment this view was
    /// fetched, so it stays a client decision - the same line [`AccessBadgeState`] draws for its
    /// "ending soon" escalation.
    pub awaiting_activation: bool,
    /// The human decision recorded on this request - the deciding approver, or the holder ending
    /// their own lease - or None when only an access rule decided it, or nothing has yet.
    ///
    /// An automatic (access-rule) decision carries no approver identity, so "who approved this"
    /// and "was this decided by a rule" are the same question, answered here once instead of by
    /// each client scanning the decision log for a non-automatic decider.
    pub human_decision: Option<AccessRequestDecisionView>,
}

impl TryFrom<AccessRequestDetailsResponseModel> for AccessRequestView {
    type Error = PamDecodeError;

    fn try_from(response: AccessRequestDetailsResponseModel) -> Result<Self, Self::Error> {
        let status = AccessRequestStatus::from(require!(response.status));
        let produced_lease_id = response.produced_lease_id.map(AccessLeaseId::new);
        let decisions = response
            .decisions
            .unwrap_or_default()
            .into_iter()
            .map(AccessRequestDecisionView::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        // An automatic decision carries no approver, so a human decision is simply one whose
        // decider is not `Automatic`. v0/v1 records at most one.
        let human_decision = decisions
            .iter()
            .find(|decision| !matches!(decision.decider, AccessDecider::Automatic))
            .cloned();

        Ok(Self {
            id: AccessRequestId::new(require!(response.id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            collection_id: CollectionId::new(require!(response.collection_id)),
            organization_id: response.organization_id.map(OrganizationId::new),
            requester_id: UserId::new(require!(response.requester_id)),
            rule_id: response.rule_id.map(AccessRuleId::new),
            status,
            lease_not_before: require!(response.lease_not_before).parse()?,
            lease_not_after: require!(response.lease_not_after).parse()?,
            reason: response.reason,
            submitted_at: require!(response.submitted_at).parse()?,
            resolved_at: response.resolved_at.map(|d| d.parse()).transpose()?,
            awaiting_activation: status == AccessRequestStatus::Approved
                && produced_lease_id.is_none(),
            human_decision,
            decisions,
            produced_lease_id,
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessPreCheckView {
    /// The cipher this pre-check was resolved for.
    pub cipher_id: CipherId,
    /// The approval path a request for this cipher would take.
    pub approval_mode: AccessApprovalMode,
    /// True when the caller already holds an active lease: reveal the credential, no request
    /// needed.
    pub has_active_lease: bool,
    /// The duration, in seconds, a request form should pre-select - the governing rule's own
    /// default where it sets one, already clamped to
    /// [`max_duration_seconds`](Self::max_duration_seconds).
    pub default_duration_seconds: u32,
    /// The longest duration (automatic path) or window span (human path), in seconds, the server
    /// will accept for this cipher: the governing rule's cap narrowed by the global ceiling.
    ///
    /// A duration picker should offer nothing above this. It is not merely advisory - submit
    /// enforces the same number and rejects a request that exceeds it.
    pub max_duration_seconds: u32,
}

impl TryFrom<AccessPreCheckResponseModel> for AccessPreCheckView {
    type Error = PamDecodeError;

    fn try_from(response: AccessPreCheckResponseModel) -> Result<Self, Self::Error> {
        // Both bounds fall back rather than `require!`: a server predating them omits both, and a
        // client that cannot read a pre-check at all cannot render a request form. Falling back to
        // the global constants reproduces the pre-per-rule-cap behaviour instead.
        let max_duration_seconds = positive_u32(response.max_duration_seconds)
            .unwrap_or(MAX_REQUEST_ACCESS_WINDOW_SECONDS)
            .min(MAX_REQUEST_ACCESS_WINDOW_SECONDS);

        Ok(Self {
            cipher_id: CipherId::new(require!(response.cipher_id)),
            approval_mode: AccessApprovalMode::from(require!(response.approval_mode)),
            has_active_lease: require!(response.has_active_lease),
            // Re-clamped here as well as server-side: the two bounds arrive as independent fields,
            // so a default above the cap would otherwise pre-fill a value submit refuses.
            default_duration_seconds: positive_u32(response.default_duration_seconds)
                .unwrap_or(DEFAULT_REQUEST_ACCESS_DURATION_SECONDS)
                .min(max_duration_seconds),
            max_duration_seconds,
        })
    }
}

/// Reads an optional wire-side duration as a positive `u32`, mapping absent, zero, and negative
/// alike onto `None` so the caller applies its fallback. Zero is not a meaningful duration bound,
/// and a negative one only arises from a malformed response.
fn positive_u32(value: Option<i32>) -> Option<u32> {
    value.filter(|v| *v > 0).map(|v| v as u32)
}

/// A decrypted view of an access request as its requester sees it right after submitting it.
///
/// A lighter sibling of [`AccessRequestView`]: the create response doesn't carry a decision log,
/// pinned rule, produced-lease linkage, or denormalized requester identity, since none of those
/// exist yet for a request that was just opened.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
    type Error = PamDecodeError;

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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
    type Error = PamDecodeError;

    fn try_from(response: AccessRequestResultResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            approval_mode: AccessApprovalMode::from(require!(response.approval_mode)),
            request: AccessRequestSummaryView::try_from(*require!(response.request))?,
        })
    }
}

/// The single badge to show for a gated cipher, derived from [`CipherAccessStateView`]'s
/// [`active_lease`](CipherAccessStateView::active_lease),
/// [`approved_request`](CipherAccessStateView::approved_request), and
/// [`pending_request`](CipherAccessStateView::pending_request) by precedence: exactly one badge
/// shows for a gated item at a time - an active lease authorizes access right now, an approved
/// request is ready to activate, and a pending request is merely awaiting a decision, so the
/// first of those that is present wins over the rest. Absent all three, the item is gated but
/// resting - no lease, no request in flight.
///
/// [`Active`](Self::Active) carries only [`expires_at`](Self::Active::expires_at). Whether that
/// time is soon enough to warrant an "ending soon" escalation is a live-countdown threshold that
/// depends on wall-clock time as the client renders it, so it stays a presentation concern for
/// the client rather than something this view decides once at fetch time.
///
/// This deliberately does not model `unavailable` (the item is currently held by another user) or
/// `expired`: the server's per-cipher access-state response is scoped to the calling user, so
/// there is no data today from which either could be derived. Producing them would need a server
/// response-model change plus a new SDK field, and is tracked separately.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum AccessBadgeState {
    /// The caller holds an active lease; the cipher is unlocked until it expires.
    Active {
        /// When the active lease's access window closes (UTC).
        #[serde(rename = "expiresAt")]
        expires_at: DateTime<Utc>,
    },
    /// The caller's request was approved and is ready to be activated into a lease.
    Ready,
    /// The caller has a request awaiting a decision.
    Pending,
    /// No active lease, approved request, or pending request - the item is gated and resting.
    Privileged,
}

/// A single-snapshot read of the caller's access state for one cipher, powering the cipher-view
/// banner and the vault-row badge.
///
/// At most one of [`active_lease`](Self::active_lease), [`pending_request`](Self::pending_request),
/// and [`approved_request`](Self::approved_request) is meaningfully "next": an active lease
/// authorizes access, a pending request awaits a decision, and an approved request awaits
/// activation by the caller. [`badge_state`](Self::badge_state) collapses those three into the
/// single badge the client should show.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
    /// The single badge to show for this cipher, derived from
    /// [`active_lease`](Self::active_lease), [`approved_request`](Self::approved_request), and
    /// [`pending_request`](Self::pending_request) by precedence. See [`AccessBadgeState`] for
    /// the precedence order and its rationale.
    pub badge_state: AccessBadgeState,
    /// Whether the active lease can still be extended.
    pub extensions_allowed: bool,
    /// The longest a single extension of the active lease may run, in seconds; None when there is
    /// no cap or no active lease.
    pub max_extension_duration_seconds: Option<i32>,
}

impl TryFrom<CipherAccessStateResponseModel> for CipherAccessStateView {
    type Error = PamDecodeError;

    fn try_from(response: CipherAccessStateResponseModel) -> Result<Self, Self::Error> {
        let active_lease = response
            .active_lease
            .map(|lease| AccessLeaseView::try_from(*lease))
            .transpose()?;
        let pending_request = response
            .pending_request
            .map(|request| AccessRequestView::try_from(*request))
            .transpose()?;
        let approved_request = response
            .approved_request
            .map(|request| AccessRequestView::try_from(*request))
            .transpose()?;

        // active lease -> approved (ready to activate) -> pending approval -> privileged
        // (resting). Mirrors the precedence documented on `AccessBadgeState`.
        let badge_state = if let Some(lease) = &active_lease {
            AccessBadgeState::Active {
                expires_at: lease.not_after,
            }
        } else if approved_request.is_some() {
            AccessBadgeState::Ready
        } else if pending_request.is_some() {
            AccessBadgeState::Pending
        } else {
            AccessBadgeState::Privileged
        };

        Ok(Self {
            cipher_id: CipherId::new(require!(response.cipher_id)),
            active_lease,
            pending_request,
            approved_request,
            badge_state,
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

/// Renders an instant for the wire as a `Z`-suffixed UTC timestamp, e.g.
/// `2025-01-01T00:00:00.000Z`.
///
/// Not [`DateTime::to_rfc3339`], which spells a zero offset `+00:00`. Both name the same instant,
/// but the server binds the requested window to a .NET `DateTime`, and its deserializer resolves
/// *any* explicit offset against the API host's timezone — handing the command a local-kind value
/// it then stores in a column read as UTC. On a host that is not UTC the window shifted by the
/// host's offset (PM-42275). A `Z` designator is the one spelling that cannot be reinterpreted, and
/// it matches what every other Bitwarden client sends (JavaScript's `toISOString()`) and what the
/// rest of this SDK writes.
fn to_wire_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

impl TryFrom<AccessRequestCreateRequest> for AccessRequestCreateRequestModel {
    type Error = AccessRequestWindowError;

    /// Validates the request's activation window on the way to the wire model.
    ///
    /// Validation lives here rather than at the call site so it cannot be circumvented: building
    /// the model *is* the only way to reach the server, so every path is checked.
    fn try_from(request: AccessRequestCreateRequest) -> Result<Self, Self::Error> {
        request.validate()?;

        Ok(Self {
            duration_seconds: request.duration_seconds.map(|d| d.get() as i32),
            start: request.start.map(to_wire_timestamp),
            end: request.end.map(to_wire_timestamp),
            reason: request.reason,
        })
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

    fn pre_check_response(
        default_duration_seconds: Option<i32>,
        max_duration_seconds: Option<i32>,
    ) -> AccessPreCheckResponseModel {
        AccessPreCheckResponseModel {
            cipher_id: Some(cipher_id()),
            approval_mode: Some(ApiAccessApprovalMode::Automatic),
            has_active_lease: Some(false),
            default_duration_seconds,
            max_duration_seconds,
            ..Default::default()
        }
    }

    #[test]
    fn pre_check_view_carries_the_rules_duration_bounds() {
        let view = AccessPreCheckView::try_from(pre_check_response(Some(900), Some(1800))).unwrap();

        assert_eq!(view.default_duration_seconds, 900);
        assert_eq!(view.max_duration_seconds, 1800);
    }

    #[test]
    fn pre_check_view_falls_back_when_bounds_are_absent() {
        // A server predating the bounds omits both; the view reproduces the previous global-only
        // behaviour rather than failing to decode.
        let view = AccessPreCheckView::try_from(pre_check_response(None, None)).unwrap();

        assert_eq!(
            view.default_duration_seconds,
            DEFAULT_REQUEST_ACCESS_DURATION_SECONDS
        );
        assert_eq!(view.max_duration_seconds, MAX_REQUEST_ACCESS_WINDOW_SECONDS);
    }

    #[test]
    fn pre_check_view_clamps_default_to_max() {
        // PM-39858's shape: a rule left at a 1h default but capped at 15m. Pre-filling the default
        // would hand the requester a duration submit refuses.
        let view = AccessPreCheckView::try_from(pre_check_response(Some(3600), Some(900))).unwrap();

        assert_eq!(view.default_duration_seconds, 900);
        assert_eq!(view.max_duration_seconds, 900);
    }

    #[test]
    fn pre_check_view_clamps_max_to_the_global_ceiling() {
        let view =
            AccessPreCheckView::try_from(pre_check_response(None, Some(7 * 86_400))).unwrap();

        assert_eq!(view.max_duration_seconds, MAX_REQUEST_ACCESS_WINDOW_SECONDS);
    }

    #[test]
    fn pre_check_view_treats_non_positive_bounds_as_absent() {
        // Zero is the client's "no cap" sentinel and never a meaningful bound; a negative value
        // only arises from a malformed response. Neither should collapse the picker to nothing.
        let view = AccessPreCheckView::try_from(pre_check_response(Some(0), Some(-1))).unwrap();

        assert_eq!(
            view.default_duration_seconds,
            DEFAULT_REQUEST_ACCESS_DURATION_SECONDS
        );
        assert_eq!(view.max_duration_seconds, MAX_REQUEST_ACCESS_WINDOW_SECONDS);
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
        assert_eq!(view.badge_state, AccessBadgeState::Privileged);
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
        // An active lease outranks the (also-populated) approved and pending requests.
        assert_eq!(
            view.badge_state,
            AccessBadgeState::Active {
                expires_at: "2025-01-01T01:00:00Z".parse().unwrap()
            }
        );
        assert!(view.extensions_allowed);
        assert_eq!(view.max_extension_duration_seconds, Some(3600));
    }

    fn cipher_access_state_response_with(
        active_lease: Option<Box<AccessLeaseResponseModel>>,
        pending_request: Option<Box<AccessRequestDetailsResponseModel>>,
        approved_request: Option<Box<AccessRequestDetailsResponseModel>>,
    ) -> CipherAccessStateResponseModel {
        CipherAccessStateResponseModel {
            cipher_id: Some(cipher_id()),
            active_lease,
            pending_request,
            approved_request,
            extensions_allowed: Some(false),
            max_extension_duration_seconds: None,
            ..Default::default()
        }
    }

    fn sample_active_lease() -> Box<AccessLeaseResponseModel> {
        Box::new(AccessLeaseResponseModel {
            id: Some(uuid!("33333333-3333-3333-3333-333333333333")),
            request_id: Some(request_id().into()),
            cipher_id: Some(cipher_id()),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
            status: Some(ApiAccessLeaseStatus::Active),
            not_before: Some("2025-01-01T00:00:00Z".to_string()),
            not_after: Some("2025-01-01T01:00:00Z".to_string()),
            ..Default::default()
        })
    }

    #[test]
    fn badge_state_is_active_when_only_an_active_lease_is_present() {
        let response = cipher_access_state_response_with(Some(sample_active_lease()), None, None);

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(
            view.badge_state,
            AccessBadgeState::Active {
                expires_at: "2025-01-01T01:00:00Z".parse().unwrap()
            }
        );
    }

    #[test]
    fn badge_state_is_ready_when_approved_request_is_present_without_a_lease() {
        let response =
            cipher_access_state_response_with(None, None, Some(Box::new(full_response())));

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(view.badge_state, AccessBadgeState::Ready);
    }

    #[test]
    fn badge_state_prefers_ready_over_pending() {
        let response = cipher_access_state_response_with(
            None,
            Some(Box::new(full_response())),
            Some(Box::new(full_response())),
        );

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(view.badge_state, AccessBadgeState::Ready);
    }

    #[test]
    fn badge_state_is_pending_when_only_a_pending_request_is_present() {
        let response =
            cipher_access_state_response_with(None, Some(Box::new(full_response())), None);

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(view.badge_state, AccessBadgeState::Pending);
    }

    #[test]
    fn badge_state_is_privileged_when_nothing_is_present() {
        let response = cipher_access_state_response_with(None, None, None);

        let view = CipherAccessStateView::try_from(response).unwrap();

        assert_eq!(view.badge_state, AccessBadgeState::Privileged);
    }

    #[test]
    fn active_badge_state_serializes_with_camel_case_expires_at() {
        let state = AccessBadgeState::Active {
            expires_at: "2025-01-01T01:00:00Z".parse().unwrap(),
        };

        let json = serde_json::to_value(&state).unwrap();

        assert_eq!(json["active"]["expiresAt"], "2025-01-01T01:00:00Z");
    }

    #[test]
    fn unit_badge_states_serialize_as_bare_strings() {
        assert_eq!(
            serde_json::to_value(AccessBadgeState::Ready).unwrap(),
            serde_json::json!("ready")
        );
        assert_eq!(
            serde_json::to_value(AccessBadgeState::Pending).unwrap(),
            serde_json::json!("pending")
        );
        assert_eq!(
            serde_json::to_value(AccessBadgeState::Privileged).unwrap(),
            serde_json::json!("privileged")
        );
    }

    #[test]
    fn access_request_create_request_converts_to_model() {
        let request = AccessRequestCreateRequest {
            duration_seconds: NonZeroU32::new(3600),
            start: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            end: Some("2025-01-01T01:00:00Z".parse().unwrap()),
            reason: Some("Need access".to_string()),
        };

        let model = AccessRequestCreateRequestModel::try_from(request).unwrap();

        assert_eq!(model.duration_seconds, Some(3600));
        assert_eq!(model.start, Some("2025-01-01T00:00:00.000Z".to_string()));
        assert_eq!(model.end, Some("2025-01-01T01:00:00.000Z".to_string()));
        assert_eq!(model.reason, Some("Need access".to_string()));
    }

    /// The window must go out `Z`-suffixed, not as a `+00:00` offset. The server resolves an
    /// explicit offset against the API host's timezone, so the offset spelling shifted the
    /// stored window by that host's offset (PM-42275). Pinned as its own test because the two
    /// spellings name the same instant and the difference is invisible to a reader of the value
    /// alone.
    #[test]
    fn access_request_create_request_window_is_serialized_as_utc_with_a_z_designator() {
        let request = AccessRequestCreateRequest {
            start: Some("2025-06-15T13:30:00.250Z".parse().unwrap()),
            end: Some("2025-06-15T14:30:00Z".parse().unwrap()),
            ..Default::default()
        };

        let model = AccessRequestCreateRequestModel::try_from(request).unwrap();

        assert_eq!(model.start, Some("2025-06-15T13:30:00.250Z".to_string()));
        assert_eq!(model.end, Some("2025-06-15T14:30:00.000Z".to_string()));
        assert!(model.start.unwrap().ends_with('Z'));
        assert!(model.end.unwrap().ends_with('Z'));
    }

    #[test]
    fn access_request_create_request_conversion_enforces_validation() {
        // Building the wire model is the only route to the server, so an invalid window cannot
        // reach it even if a caller skips the client method.
        let request = AccessRequestCreateRequest {
            start: Some("2025-01-01T01:00:00Z".parse().unwrap()),
            end: Some("2025-01-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };

        let result = AccessRequestCreateRequestModel::try_from(request);

        assert_eq!(
            result.unwrap_err(),
            AccessRequestWindowError::EndBeforeStart
        );
    }

    #[test]
    fn awaiting_activation_is_true_for_an_approved_request_with_no_lease_yet() {
        let response = AccessRequestDetailsResponseModel {
            status: Some(ApiAccessRequestStatus::Approved),
            produced_lease_id: None,
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert!(view.awaiting_activation);
    }

    /// Activation does not change the status, so only the minted lease separates "still to start"
    /// from "already running".
    #[test]
    fn awaiting_activation_is_false_once_the_request_has_minted_a_lease() {
        let response = AccessRequestDetailsResponseModel {
            status: Some(ApiAccessRequestStatus::Approved),
            produced_lease_id: Some(Uuid::new_v4()),
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert!(!view.awaiting_activation);
        assert_eq!(view.status, AccessRequestStatus::Approved);
    }

    #[test]
    fn awaiting_activation_is_false_for_a_request_still_pending() {
        let response = AccessRequestDetailsResponseModel {
            status: Some(ApiAccessRequestStatus::Pending),
            produced_lease_id: None,
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert!(!view.awaiting_activation);
    }

    #[test]
    fn human_decision_skips_the_automatic_one() {
        let response = AccessRequestDetailsResponseModel {
            decisions: Some(vec![automatic_decision(), human_decision()]),
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        let decision = view.human_decision.expect("a human decided this request");
        assert!(matches!(decision.decider, AccessDecider::Human(_)));
        assert_eq!(decision.comment.as_deref(), Some("Looks fine"));
    }

    #[test]
    fn human_decision_is_none_when_only_an_access_rule_decided() {
        let response = AccessRequestDetailsResponseModel {
            decisions: Some(vec![automatic_decision()]),
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert!(view.human_decision.is_none());
    }

    #[test]
    fn human_decision_is_none_while_the_request_is_undecided() {
        let response = AccessRequestDetailsResponseModel {
            decisions: Some(vec![]),
            ..full_response()
        };

        let view = AccessRequestView::try_from(response).unwrap();

        assert!(view.human_decision.is_none());
    }
}
