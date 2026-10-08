#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod agent_fill_client;
pub mod approvals;

pub use agent_fill_client::{AgentFillClient, AgentFillClientExt};
pub use approvals::{
    AgentFillApprovalClient, AgentFillApprovalError, AgentFillApprovalId, ApprovalCipherType,
    ApprovalDecision, ApprovalRequestView, Challenge, CreatedApprovalRequest, DenyReason,
    OpenedApprovalRequest, PendingApproval,
};
