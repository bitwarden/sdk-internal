//! PAM access request operations.
//!
//! An *access request* is a member's ask to open a PAM-gated cipher. Once approved, the requester
//! [`activate`](AccessRequestsClient::activate)s it to mint a short-lived lease over the cipher.

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
pub use validate::{
    AccessRequestWindowError, DEFAULT_REQUEST_ACCESS_DURATION_SECONDS,
    MAX_REQUEST_ACCESS_WINDOW_SECONDS, default_request_access_duration_seconds,
    max_request_access_window_seconds,
};
