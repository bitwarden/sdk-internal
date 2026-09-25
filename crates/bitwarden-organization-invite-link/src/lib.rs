#![doc = include_str!("../README.md")]

mod invite_link_client;
mod organization_invite_link;
mod server_error;
pub use invite_link_client::{
    AcceptInviteLinkError, InviteLinkClient, InviteLinkClientExt, InviteLinkError,
};
pub use organization_invite_link::OrganizationInviteLink;
