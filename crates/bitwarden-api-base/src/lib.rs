#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

mod client;
#[cfg(not(target_arch = "wasm32"))]
mod client_certificate;
mod configuration;
mod error;
mod request;
mod status_code_serializer;
mod util;

#[cfg(not(target_arch = "wasm32"))]
pub use client::new_http_client_builder_with_client_certificate;
pub use client::{new_http_client, new_http_client_builder};
#[cfg(not(target_arch = "wasm32"))]
pub use client_certificate::{
    ClientCertSigner, ClientCertSignerError, ClientCertificate, TlsSigScheme,
};
pub use configuration::Configuration;
pub use error::{ApiError, Error, ResponseContent};
pub use request::{process_with_empty_response, process_with_json_response};
pub use util::{AuthRequired, ContentType, parse_deep_object, urlencode};
