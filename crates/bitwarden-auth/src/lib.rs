#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod auth_client;

pub mod send_access;

pub(crate) mod api; // keep internal to crate

pub use auth_client::{AuthClient, AuthClientExt};
