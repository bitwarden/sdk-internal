#![doc = include_str!("../README.md")]

mod auth_client;
mod common;
mod send_access;

pub use auth_client::{AuthClient, AuthClientExt};
pub use common::enums::{GrantType, Scope};
pub use send_access::{
    SendAccessClient, SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest,
    SendAccessTokenResponse,
};
