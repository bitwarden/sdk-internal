#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

#[allow(missing_docs)]
pub mod access_token;
pub(crate) mod access_token_request;
pub mod auth_client;
pub mod client;
mod client_projects;
mod client_secrets;
mod error;
pub(crate) mod login_access_token;
pub(crate) mod login_types;
#[allow(missing_docs)]
pub mod projects;
#[allow(missing_docs)]
pub mod secrets;
pub(crate) mod service_account_login_method;
pub(crate) mod state;
mod token_handler;

pub use access_token::{AccessToken, AccessTokenInvalidError};
pub use bitwarden_core::DeviceType;
pub use client::{ClientSettings, SecretsManagerClient};
pub use client_projects::ProjectsClient;
pub use client_secrets::SecretsClient;
pub use login_types::{AccessTokenLoginRequest, AccessTokenLoginResponse};
pub use token_handler::SecretsManagerTokenHandler;
