#![doc = include_str!("../README.md")]

mod accept;
mod approve;
mod confirm;
mod delete;
mod emergency_access;
mod emergency_access_client;
mod get;
mod get_grantor_policies;
mod initiate;
mod invite;
mod list_granted;
mod list_trusted;
mod reinvite;
mod reject;
mod takeover;
#[cfg(test)]
mod test_support;
mod update;
mod view_vault_items;

pub use accept::EmergencyAccessAcceptError;
pub use approve::EmergencyAccessApproveError;
pub use confirm::EmergencyAccessConfirmError;
pub use delete::EmergencyAccessDeleteError;
pub use emergency_access::{
    EmergencyAccessId, EmergencyAccessStatus, EmergencyAccessType, GranteeEmergencyAccess,
    GrantorEmergencyAccess,
};
pub use emergency_access_client::{EmergencyAccessClient, EmergencyAccessClientExt};
pub use get::EmergencyAccessGetError;
pub use get_grantor_policies::EmergencyAccessGetGrantorPoliciesError;
pub use initiate::EmergencyAccessInitiateError;
pub use invite::EmergencyAccessInviteError;
pub use list_granted::EmergencyAccessListGrantedError;
pub use list_trusted::EmergencyAccessListTrustedError;
pub use reinvite::EmergencyAccessReinviteError;
pub use reject::EmergencyAccessRejectError;
pub use takeover::EmergencyAccessTakeoverError;
pub use update::EmergencyAccessUpdateError;
pub use view_vault_items::EmergencyAccessViewError;
