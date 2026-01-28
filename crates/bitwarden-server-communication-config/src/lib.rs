//! Server communication configuration management for SSO cookie handling
//!
//! This crate provides data structures and storage abstractions for managing
//! server communication configuration, particularly for SSO load balancer cookies
//! used in self-hosted environments.

#![deny(missing_docs)]

mod client;
mod config;
mod repository;

pub use client::ServerCommunicationConfigClient;
pub use config::{BootstrapConfig, ServerCommunicationConfig, SsoCookieVendorConfig};
pub use repository::{
    ServerCommunicationConfigRepository, ServerCommunicationConfigRepositoryError,
};

#[cfg(feature = "wasm")]
/// WASM bindings for JavaScript interoperability
pub mod wasm;
