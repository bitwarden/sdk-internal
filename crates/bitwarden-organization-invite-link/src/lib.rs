#![doc = include_str!("../README.md")]

mod invite;
pub use invite::{
    OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError,
    generate_organization_invite_crypto_bundle, unseal_organization_invite_key,
};
