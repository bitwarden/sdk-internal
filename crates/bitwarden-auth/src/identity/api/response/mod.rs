//! Response models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the identity
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod login_success_api_response;
pub(crate) use login_success_api_response::LoginSuccessApiResponse;

mod user_decryption_options_response;
pub(crate) use user_decryption_options_response::UserDecryptionOptionsResponse;

mod login_error_api_response;
pub(crate) use login_error_api_response::LoginErrorApiResponse;
