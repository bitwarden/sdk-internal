#![doc = include_str!("../README.md")]

mod invite_link_client;
mod organization_invite_link;
pub use invite_link_client::{InviteLinkClient, InviteLinkClientExt, InviteLinkError};
pub use organization_invite_link::OrganizationInviteLink;
