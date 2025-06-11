//! Platform code
//!
//! Currently contains logic for generation of fingerprints and fetching a users api key.

mod generate_fingerprint;
mod get_user_api_key;
mod platform_client;
mod secret_verification_request;
mod state_client;

pub use generate_fingerprint::{
    FingerprintError, FingerprintRequest, FingerprintResponse, UserFingerprintError,
};
pub(crate) use get_user_api_key::get_user_api_key;
pub use get_user_api_key::{UserApiKeyError, UserApiKeyResponse};
pub use platform_client::PlatformClient;
pub use secret_verification_request::SecretVerificationRequest;
pub use state_client::StateClient;
