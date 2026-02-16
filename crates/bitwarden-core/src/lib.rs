#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

pub mod auth;
pub mod client;
mod error;
pub mod key_management;
pub use error::{
    ApiError, MissingFieldError, MissingPrivateKeyError, NotAuthenticatedError, WrongPasswordError,
};
#[cfg(feature = "internal")]
pub mod mobile;
#[cfg(feature = "internal")]
pub mod platform;
#[cfg(feature = "secrets")]
pub mod secrets_manager;

/// Derive macro for implementing the [`FromClient`] trait.
///
/// See [`FromClient`] for usage details.
pub use bitwarden_core_macro::FromClient;
pub use bitwarden_crypto::ZeroizingAllocator;
pub use client::{Client, ClientSettings, DeviceType, FromClient};

mod ids;
pub use ids::*;
