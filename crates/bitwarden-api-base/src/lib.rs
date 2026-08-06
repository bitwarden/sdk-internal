#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

mod client;
mod configuration;
mod error;
mod request;
mod status_code_serializer;
mod util;

pub use client::{new_http_client, new_http_client_builder};
pub use configuration::Configuration;
pub use error::{ApiError, Error, ResponseContent};
pub use request::{process_with_empty_response, process_with_json_response};
pub use util::{AuthRequired, ContentType, parse_deep_object, urlencode};
