//! Response models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the identity
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod login_api_success_response;
pub(crate) use login_api_success_response::LoginApiSuccessResponse;

mod user_decryption_options_response;
pub(crate) use user_decryption_options_response::UserDecryptionOptionsResponse;
