//! PAM approver operations.

mod client;
mod error;
mod models;

pub use client::ApprovalsClient;
pub use error::ApprovalError;
pub use models::AccessDecisionRequest;
