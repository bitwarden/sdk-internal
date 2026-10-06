//! PAM approver operations.
//!
//! The approver side of the request lifecycle
//! ([`AccessRequestsClient`](crate::AccessRequestsClient) covers the requester side).
//! [`ApprovalsClient`] lists inbox and history requests, and decides a pending one.

mod client;
mod error;
mod models;

pub use client::ApprovalsClient;
pub use error::ApprovalError;
pub use models::AccessDecisionRequest;
