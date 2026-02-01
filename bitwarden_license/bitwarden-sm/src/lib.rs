#![doc = include_str!("../README.md")]

pub mod client;
mod client_projects;
mod client_secrets;
mod error;
#[allow(missing_docs)]
pub mod projects;
#[allow(missing_docs)]
pub mod secrets;

pub use bitwarden_core::auth::{
    AccessToken,
    login::{AccessTokenLoginRequest, AccessTokenLoginResponse},
};
pub use client::{ClientSettings, SecretsManagerClient};
pub use client_projects::ProjectsClient;
pub use client_secrets::SecretsClient;
