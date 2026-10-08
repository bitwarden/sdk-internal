//! Sealing, opening and verifying agent fill approval requests and responses.

mod approval_client;
mod challenge;
mod error;
mod request;
mod response;
mod sealed;

pub use approval_client::{
    AgentFillApprovalClient, CreatedApprovalRequest, OpenedApprovalRequest, PendingApproval,
};
use bitwarden_uuid::uuid_newtype;
pub use challenge::Challenge;
pub use error::AgentFillApprovalError;
pub use request::{ApprovalCipherType, ApprovalRequestView};
pub use response::{ApprovalDecision, DenyReason};

uuid_newtype!(pub AgentFillApprovalId);
