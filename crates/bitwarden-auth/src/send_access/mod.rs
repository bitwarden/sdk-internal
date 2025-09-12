//! The SendAccess module handles send access token requests and responses.
//! We use a custom extension OAuth2 grant type to request send access tokens
//! outside the context of a Bitwarden user. This will be used by the send portion of the
//! Bitwarden web app to allow users to access send access functionality without
//! needing to log in to a Bitwarden account.
//! Sends can be anonymous, password protected, or email protected.
//! If you request an access token for an anonymous send by id, no credentials are required.
//! If you request an access token for a password protected send, you must provide a correct
//! password hash. If you request an access token for an email protected send, you must provide the
//! email address and a one-time passcode (OTP) sent to that email address.
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
