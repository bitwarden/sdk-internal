#![doc = include_str!("../README.md")]

mod client_projects;
mod client_secrets;
mod error;
#[allow(missing_docs)]
pub mod projects;
#[allow(missing_docs)]
pub mod secrets;

pub use client_projects::{ClientProjects, ClientProjectsExt, ProjectsClient, ProjectsClientExt};
pub use client_secrets::{ClientSecrets, ClientSecretsExt, SecretsClient, SecretsClientExt};
