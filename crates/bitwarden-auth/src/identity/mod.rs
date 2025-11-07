//! Identity client module
//! The IdentityClient is used to obtain identity / access tokens from the Bitwarden Identity API.
mod client;

pub use client::{IdentityClient, PasswordPreloginData, PasswordPreloginError};
