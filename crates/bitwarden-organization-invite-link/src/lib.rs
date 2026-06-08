#![doc = include_str!("../README.md")]

mod invite_link_client;
pub use invite_link_client::{
    InviteLinkClient, InviteLinkClientExt, OrganizationInviteCryptoBundle,
    OrganizationInviteCryptoBundleError,
};
