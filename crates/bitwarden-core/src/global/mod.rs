//! Unauthenticated client used by the CLI runtime and other contexts that need
//! to make API calls before (or without) a signed-in user.
//!
//! Unlike [`crate::Client`], a [`GlobalClient`] does not bind to a `UserId`,
//! does not hold key material, and does not resolve API URLs at construction.
//! Each operation chooses the URL it needs at call time via
//! [`GlobalClient::make_api_client`] /
//! [`GlobalClient::make_identity_client`].

mod global_client;
mod global_internal_client;

pub use global_client::GlobalClient;
pub(crate) use global_internal_client::GlobalInternalClient;
