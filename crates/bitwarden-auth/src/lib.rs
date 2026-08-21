#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod auth_client;

#[allow(missing_docs)]
pub mod access_token;
pub mod login;
pub mod registration;
pub mod send_access;
#[allow(missing_docs)]
pub mod service_account_login_method;
#[allow(missing_docs)]
pub mod sm_request;
pub mod token_management;

pub(crate) mod api; // keep internal to crate

pub use access_token::{AccessToken, AccessTokenInvalidError};
pub use auth_client::{AuthClient, AuthClientExt};
