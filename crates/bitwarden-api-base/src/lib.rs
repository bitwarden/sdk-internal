//! Base types and utilities for Bitwarden API clients.
//!
//! This crate provides common functionality shared across all Bitwarden API client crates:
//! - Configuration types for API clients
//! - Error handling types
//! - URL encoding and query parameter utilities

mod configuration;
mod error;
mod util;

pub use configuration::Configuration;
pub use error::{Error, ResponseContent};
pub use util::{AuthRequired, ContentType, parse_deep_object, urlencode};
