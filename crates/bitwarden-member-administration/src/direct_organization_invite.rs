use bitwarden_core::OrganizationId;
use bitwarden_organizations::OrganizationUserId;
use serde::{Deserialize, Serialize};

/// A direct invitation to join an organization, accepted without a prior master password
/// confirmation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum DirectOrganizationInvite {
    /// An invite to an organization that already exists and has been initialized.
    ExistingOrganization {
        /// The organization the user was invited to.
        organization_id: OrganizationId,
        /// The membership being accepted.
        organization_user_id: OrganizationUserId,
        /// The email address the invite was sent to.
        email: String,
        /// The invite token issued by the server.
        token: String,
    },
    /// An invite to an organization that has not yet been initialized by its owner.
    PendingOrganization {
        /// The organization the user was invited to.
        organization_id: OrganizationId,
        /// The membership being accepted.
        organization_user_id: OrganizationUserId,
        /// The invite token issued by the server.
        token: String,
        /// The name to give the organization's default collection on initialization.
        default_collection_name: String,
    },
}
