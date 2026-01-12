#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod auth_client;

pub mod identity;
pub mod registration;
pub mod send_access;

pub(crate) mod api; // keep internal to crate

pub use auth_client::{AuthClient, AuthClientExt};
