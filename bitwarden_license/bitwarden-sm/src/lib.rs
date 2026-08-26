#![doc = include_str!("../README.md")]

pub mod auth_client;
pub mod client;
mod client_projects;
mod client_secrets;
mod error;
pub(crate) mod login_access_token;
#[allow(missing_docs)]
pub mod projects;
#[allow(missing_docs)]
pub mod secrets;
pub(crate) mod state;
#[cfg(test)]
pub(crate) mod test_utils;
mod token_handler;

pub use bitwarden_auth::{
    AccessToken,
    login::access_token::{AccessTokenLoginRequest, AccessTokenLoginResponse},
};
pub use bitwarden_core::DeviceType;
pub use client::{ClientSettings, SecretsManagerClient};
pub use client_projects::ProjectsClient;
pub use client_secrets::SecretsClient;
pub use token_handler::SecretsManagerTokenHandler;
