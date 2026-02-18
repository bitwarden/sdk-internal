//! This module contains request/response models used internally when communicating
//! with the Bitwarden Identity API. These are implementation details and should not
//! be exposed in the public SDK surface.

/// API related modules for Identity endpoints
pub(crate) mod request;
pub(crate) mod response;

/// Common send function for login requests
mod send_login_request;
pub(crate) use send_login_request::send_login_request;
