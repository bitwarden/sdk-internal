#![doc = include_str!("../README.md")]

mod auth_client;
mod send_access;

pub use auth_client::{AuthClient, AuthClientExt};
