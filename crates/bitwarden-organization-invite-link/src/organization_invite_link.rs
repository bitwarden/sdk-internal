use bitwarden_api_api::models::{
    OrganizationInviteLinkResponseModel, OrganizationInviteLinkSsoResponseModel,
    OrganizationInviteLinkStatusResponseModel,
};
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::KeyStoreContext;
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
                .map_err(|_| InviteLinkError::ParseFailure("creation_date"))?,
        })
    }
}

impl OrganizationInviteLink {
    /// Converts the invite link to a view model with URL for display.
    pub fn to_view(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<OrganizationInviteLinkView, InviteLinkError> {
        let org_id = self.organization_id;

        // Unwrap the invite secret
        let org_key = SymmetricKeySlotId::Organization(org_id);
        let invite_key = self
            .invite
            .unseal_invite_key_with_organization_key(org_key, ctx)?;
        let invite_secret = self.invite.get_invite_secret(invite_key, ctx)?;

        let invite_secret_str: String = (&invite_secret).into();
        let code = self.code;
        let url_fragment = format!("/join/{org_id}/{code}?key={invite_secret_str}");

        Ok(OrganizationInviteLinkView {
            id: self.id,
            organization_id: self.organization_id,
            allowed_domains: self.allowed_domains,
            supports_confirmation: self.supports_confirmation,
            creation_date: self.creation_date,
            url_fragment,
        })
    }
}

/// An organization invite link with reconstructed URL for display by the client.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteLinkView {
    /// Unique identifier of the invite link.
    pub id: Uuid,
    /// The organization this invite link belongs to.
    pub organization_id: OrganizationId,
    /// Email domains permitted to redeem this invite link.
    pub allowed_domains: Vec<String>,
    /// Whether invitees can self-confirm using this invite link.
    pub supports_confirmation: bool,
    /// When the invite link was created.
    pub creation_date: DateTime<Utc>,
    /// The invite link URL fragment (to be appended on the web vault URL)
    pub url_fragment: String,
}

/// The status of an organization invite link, used to verify basic availability before an invitee
/// attempts to accept.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteLinkStatusView {
    /// The name of the organization the invite link belongs to.
    pub organization_name: String,
    /// Whether invite links are currently enabled for the organization.
    pub links_enabled: bool,
    /// Whether the organization has seats available for new members.
    pub seats_available: bool,
    /// Whether invitees can self-confirm using this invite link.
    pub supports_confirmation: bool,
    /// SSO details for the organization, when SSO is configured.
    pub sso: Option<OrganizationInviteLinkSsoView>,
}

/// SSO details for an organization referenced by an invite link status.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteLinkSsoView {
    /// The organization's SSO identifier, when configured.
    pub org_sso_id: Option<String>,
    /// Whether SSO is required to redeem this invite link.
    pub required: bool,
}

impl From<OrganizationInviteLinkSsoResponseModel> for OrganizationInviteLinkSsoView {
    fn from(response: OrganizationInviteLinkSsoResponseModel) -> Self {
        Self {
            org_sso_id: response.org_sso_id,
            required: response.required.unwrap_or(false),
        }
    }
}

impl TryFrom<OrganizationInviteLinkStatusResponseModel> for OrganizationInviteLinkStatusView {
    type Error = InviteLinkError;

    fn try_from(response: OrganizationInviteLinkStatusResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            organization_name: require!(response.organization_name),
            links_enabled: response.links_enabled.unwrap_or(false),
            seats_available: response.seats_available.unwrap_or(false),
            supports_confirmation: response.supports_confirmation.unwrap_or(false),
            sso: response.sso.map(|sso| (*sso).into()),
        })
    }
}
