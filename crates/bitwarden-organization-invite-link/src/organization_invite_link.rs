use bitwarden_api_api::models::OrganizationInviteLinkResponseModel;
use bitwarden_core::{OrganizationId, require};
use bitwarden_organization_crypto::invite::Invite;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;

use crate::InviteLinkError;

/// An organization invite link as persisted by the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteLink {
    /// Unique identifier of the invite link.
    pub id: Uuid,
    /// The invite code invitees present when accepting or confirming the invite.
    pub code: Uuid,
    /// The organization this invite link belongs to.
    pub organization_id: OrganizationId,
    /// Email domains permitted to redeem this invite link.
    pub allowed_domains: Vec<String>,
    /// The sealed cryptographic invite carried in the invite link.
    pub invite: Invite,
    /// Whether invitees can self-confirm using this invite link.
    pub supports_confirmation: bool,
    /// When the invite link was created.
    pub creation_date: DateTime<Utc>,
}

impl TryFrom<OrganizationInviteLinkResponseModel> for OrganizationInviteLink {
    type Error = InviteLinkError;

    fn try_from(response: OrganizationInviteLinkResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: require!(response.id),
            code: require!(response.code),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            allowed_domains: response.allowed_domains.unwrap_or_default(),
            invite: require!(response.invite).parse()?,
            supports_confirmation: response.supports_confirmation.unwrap_or(false),
            creation_date: require!(response.creation_date)
                .parse()
                .map_err(|_| InviteLinkError::MalformedField("creation_date"))?,
        })
    }
}
