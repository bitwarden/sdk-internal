//! Request models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the identity
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod login_api_request;
// STANDARD_USER_SCOPES is used in tests in password_login_api_request.rs
#[allow(unused_imports)]
pub(crate) use login_api_request::{LoginApiRequest, STANDARD_USER_SCOPES};
