//! Identity client module
//! The IdentityClient is used to obtain identity / access tokens from the Bitwarden Identity API.
mod client;
/// Password-based authentication functionality
mod password_login;

pub use client::IdentityClient;
pub use password_login::{PasswordPreloginData, PasswordPreloginError};
