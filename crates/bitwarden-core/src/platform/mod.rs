//! Platform code
//!
//! Currently contains logic for generation of fingerprints and fetching a users api key.

mod generate_fingerprint;
mod get_user_api_key;
pub mod platform_client;
mod secret_verification_request;

pub use generate_fingerprint::{
    FingerprintError, FingerprintRequest, FingerprintResponse, UserFingerprintError,
};
pub(crate) use get_user_api_key::get_user_api_key;
pub use get_user_api_key::{UserApiKeyError, UserApiKeyResponse};
pub use secret_verification_request::SecretVerificationRequest;
