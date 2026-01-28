//! Login client module
//! The LoginClient is used to authenticate a Bitwarden User.
//! This involves logging in via various mechanisms (password, SSO, etc.) to obtain
//! OAuth2 tokens from the BW Identity API.
mod login_client;

pub use login_client::LoginClient;

/// Models used by the login module
pub mod models;

/// Login via password functionality
pub mod login_via_password;

// API models should be private to the login module as they are only used internally.
pub(crate) mod api;
