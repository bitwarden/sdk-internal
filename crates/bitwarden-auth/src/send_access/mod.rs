mod access_token_request;
mod access_token_response;
mod client;

pub mod api;

pub use access_token_request::{
    SendAccessCredentials, SendAccessTokenRequest, SendEmailCredentials, SendEmailOtpCredentials,
    SendPasswordCredentials,
};
pub use access_token_response::{
    SendAccessTokenError, SendAccessTokenResponse, UnexpectedIdentityError,
};
pub use client::SendAccessClient;
