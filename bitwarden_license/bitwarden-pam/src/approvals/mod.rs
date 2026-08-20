//! PAM approver operations.
//!
//! This is the *approver* side of the same request lifecycle the requester side covers in
//! [`AccessRequestsClient`](crate::AccessRequestsClient): an approver reads the requests awaiting
//! their decision, reads the ones they've already decided, and records a decision on a pending
//! request.
//!
//! [`ApprovalsClient`] is obtained from the [`PamClient`](crate::PamClient) and covers
//! [`list_inbox`](ApprovalsClient::list_inbox)ing pending requests the caller may decide,
//! [`list_history`](ApprovalsClient::list_history)ing the ones they've decided, and
//! [`decide`](ApprovalsClient::decide)ing a pending request.

mod client;
mod error;
mod models;

pub use client::ApprovalsClient;
pub use error::AccessDecisionError;
pub use models::AccessDecisionRequest;
