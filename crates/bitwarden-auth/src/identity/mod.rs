//! Identity client module
//! The IdentityClient is used to obtain identity / access tokens from the Bitwarden Identity API.
mod identity_client;

pub use identity_client::IdentityClient;

/// Models used by the identity module
pub mod models;

/// Login via password functionality
pub mod login_via_password;

// API models should be private to the identity module as they are only used internally.
pub(crate) mod api_models;
