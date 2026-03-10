//! The Login module provides the LoginClient and related types for authenticating
//! Bitwarden users via various mechanisms (password, SSO, etc.) to obtain
//! OAuth2 tokens from the Bitwarden Identity API.

mod login_client;

pub use login_client::LoginClient;

pub mod models;

pub mod login_via_password;

// API models should be private to the login module as they are only used internally.
pub(crate) mod api;
