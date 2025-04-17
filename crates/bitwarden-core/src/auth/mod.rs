//! Authentication module
//!
//! Contains all the authentication related functionality for registering and logging in.

use thiserror::Error;

use crate::{NotAuthenticatedError, VaultLockedError, WrongPasswordError};

mod access_token;
pub(super) mod api;
pub mod auth_client;
mod jwt_token;
pub mod login;
#[cfg(feature = "internal")]
pub mod password;
#[cfg(feature = "internal")]
pub mod pin;
pub mod renew;
pub use access_token::{AccessToken, AccessTokenInvalidError};
pub use jwt_token::*;

#[cfg(feature = "internal")]
mod auth_request;
#[cfg(feature = "internal")]
pub(crate) use auth_request::{auth_request_decrypt_master_key, auth_request_decrypt_user_key};
#[cfg(feature = "internal")]
pub use auth_request::{ApproveAuthRequestError, AuthRequestResponse};

#[cfg(feature = "internal")]
mod register;
#[cfg(feature = "internal")]
pub use register::{RegisterError, RegisterKeyResponse, RegisterRequest};

#[cfg(feature = "internal")]
mod tde;
#[cfg(feature = "internal")]
pub use tde::RegisterTdeKeyResponse;
#[cfg(feature = "internal")]
mod key_connector;
#[cfg(feature = "internal")]
pub use key_connector::KeyConnectorResponse;

/// Error for authentication related operations
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum AuthValidateError {
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    WrongPassword(#[from] WrongPasswordError),
    #[error(transparent)]
    VaultLocked(#[from] VaultLockedError),
    #[error("wrong user key")]
    WrongUserKey,
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}
