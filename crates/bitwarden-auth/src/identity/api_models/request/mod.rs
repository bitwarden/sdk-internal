//! Request models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the identity
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod user_login_api_request;
pub(crate) use user_login_api_request::UserLoginApiRequest;
