#![doc = include_str!("../README.md")]
//! # Bitwarden Noise Client
//!
//! This crate provides a remote client implementation for connecting to
//! a Bitwarden user-client through a proxy using the Noise Protocol.
//!
//! ## Features
//!
//! - PSK-based authentication using pairing codes
//! - Noise Protocol XX pattern with PSK for secure channel establishment
//! - Session caching for reconnection without re-pairing
//! - Static keypair storage for persistent device identity
//!
//! ## Usage
//!
//! ```ignore
//! use bitwarden_noise_client::{RemoteClient, RemoteClientConfig};
//! use tokio::sync::mpsc;
//!
//! let config = RemoteClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     username: "user@example.com".to_string(),
//!     pairing_code: "K7X9:eyJz...".to_string(),
//!     client_id: Some("my-device".to_string()),
//!     use_cached_auth: true,
//! };
//!
//! let (event_tx, mut event_rx) = mpsc::channel(32);
//! let mut client = RemoteClient::new(None);
//!
//! client.connect(config, event_tx).await?;
//!
//! let credential = client.request_credential("example.com").await?;
//! ```

/// Remote client for connecting through proxy
mod client;

/// Error types
pub mod error;

/// Static keypair storage
pub mod keypair_storage;

/// Session cache for PSK persistence
pub mod session_cache;

/// Protocol types and events
pub mod types;

pub use client::RemoteClient;
pub use error::RemoteClientError;
pub use keypair_storage::{
    clear_all_keypairs, delete_static_keypair, get_or_create_static_keypair, has_static_keypair,
    list_devices,
};
pub use session_cache::SessionCache;
pub use types::{CredentialData, RemoteClientConfig, RemoteClientEvent};
