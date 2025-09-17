#![doc = include_str!("../README.md")]

mod auth_client;

pub mod send_access;

pub(crate) mod api; // keep internal to crate

pub use auth_client::{AuthClient, AuthClientExt};
