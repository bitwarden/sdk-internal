#![doc = include_str!("../README.md")]

#[allow(missing_docs)]
pub mod access_policies;
pub mod client;
mod client_access_policies;
mod client_projects;
mod client_secrets;
mod error;
#[allow(missing_docs)]
pub mod projects;
#[allow(missing_docs)]
pub mod secrets;

// Re-exports for backwards compatibility with sdk-sm consumers that import via bitwarden_sm::*
pub use bitwarden_core::{
    ClientSettings, DeviceType,
    auth::{
        AccessToken,
        login::{AccessTokenLoginRequest, AccessTokenLoginResponse},
    },
};
pub use client::SecretsManagerClient;
pub use client_access_policies::{AccessPoliciesClient, AccessPoliciesClientExt};
pub use client_projects::ProjectsClient;
pub use client_secrets::SecretsClient;
