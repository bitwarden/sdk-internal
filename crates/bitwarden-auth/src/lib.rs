#![doc = include_str!("../README.md")]

mod auth_client;
mod common;

/// Module for handling Send Access token requests and responses.
pub mod send_access;

pub use auth_client::{AuthClient, AuthClientExt};
pub use common::enums::{GrantType, Scope};
