#![doc = include_str!("../README.md")]

mod client;
mod configuration;
mod error;
mod request;
mod util;

pub use client::{new_http_client, new_http_client_builder};
pub use configuration::Configuration;
pub use error::{Error, ResponseContent};
pub use request::{process_with_empty_response, process_with_json_response};
pub use util::{AuthRequired, ContentType, parse_deep_object, urlencode};
