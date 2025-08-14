mod access_token_request;
mod access_token_response;
mod client;

/// Submodule containing the Send Access API request and response types.
pub mod api;

pub use access_token_request::{
    SendAccessCredentials, SendAccessTokenRequest, SendEmailCredentials, SendEmailOtpCredentials,
    SendPasswordCredentials,
};
pub use access_token_response::{SendAccessTokenError, SendAccessTokenResponse};
pub use client::SendAccessClient;
