//! Request models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the login
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod login_api_request;
#[allow(
    unused_imports,
    reason = "STANDARD_USER_SCOPES is used in tests in password_login_api_request.rs"
)]
pub(crate) use login_api_request::{LoginApiRequest, STANDARD_USER_SCOPES};
