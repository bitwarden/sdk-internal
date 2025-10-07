//! Authentication module
//!
//! Contains all the authentication related functionality for registering and logging in.

use thiserror::Error;

use crate::{NotAuthenticatedError, WrongPasswordError};

mod access_token;
// API is intentionally not visible outside of `auth` as these should be considered private.
mod api;
#[cfg(feature = "internal")]
pub(crate) use api::response::user_decryption_options_response::UserDecryptionOptionsResponseModel;
#[allow(missing_docs)]
pub mod auth_client;
mod jwt_token;
#[allow(missing_docs)]
pub mod login;
#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod password;
#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod pin;
#[allow(missing_docs)]
pub mod renew;
pub use access_token::{AccessToken, AccessTokenInvalidError};
pub use jwt_token::*;

#[cfg(feature = "internal")]
mod auth_request;
#[cfg(feature = "internal")]
pub use auth_request::{ApproveAuthRequestError, AuthRequestResponse};
#[cfg(feature = "internal")]
pub(crate) use auth_request::{auth_request_decrypt_master_key, auth_request_decrypt_user_key};

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
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum AuthValidateError {
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    WrongPassword(#[from] WrongPasswordError),
    #[error("wrong user key")]
    WrongUserKey,
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}
