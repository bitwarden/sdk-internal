//! PAM access request operations.
//!
//! An *access request* is a member's ask to open a PAM-gated cipher. A requester
//! [`pre_check`](AccessRequestsClient::pre_check)s a cipher to learn whether a request would be
//! auto-approved, then [`request`](AccessRequestsClient::request)s access. On the automatic (no
//! human approval) path the server auto-approves it, and the requester
//! [`activate`](AccessRequestsClient::activate)s the approved request to mint a short-lived
//! [`AccessLease`](crate::AccessLeaseView) over the cipher.
//!
//! [`AccessRequestsClient`] is obtained from the [`PamClient`](crate::PamClient) and covers
//! per-cipher access-state reads, opening a request, listing/reading the caller's requests,
//! activating an approved one, and cancelling a pending one.

mod client;
mod error;
mod models;
mod validate;

pub use client::AccessRequestsClient;
pub use error::AccessRequestError;
pub use models::{
    AccessApprovalMode, AccessApprover, AccessBadgeState, AccessDecider, AccessDecisionVerdict,
    AccessPreCheckView, AccessRequestCreateRequest, AccessRequestDecisionView,
    AccessRequestResultView, AccessRequestStatus, AccessRequestSummaryView, AccessRequestView,
    CipherAccessStateView,
};
pub use validate::AccessRequestWindowError;
