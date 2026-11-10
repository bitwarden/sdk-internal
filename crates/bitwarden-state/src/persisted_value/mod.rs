//! Type-safe persisted values API for storing application configuration and state.
//!
//! This module provides a type-safe key-value API for storing persisted values. Each persisted
//! value resolves to its own backend, defaulting to the SDK-managed database.
//!
//! # Usage
//!
//! ```rust,ignore
//! use bitwarden_state::register_persisted_value;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct AppConfig {
//!     theme: String,
//!     auto_save: bool,
//! }
//!
//! // Register a type-safe key
//! register_persisted_value!(CONFIG: AppConfig = "app_config");
//!
//! // Access persisted values via client.platform().state().value()
//! async fn example(client: &bitwarden_core::Client) -> Result<(), Box<dyn std::error::Error>> {
//!     // Get a persisted value handle
//!     let value = client.platform().state().value::<CONFIG>();
//!
//!     // Get value
//!     let config: Option<AppConfig> = value.try_get().await?;
//!
//!     // Update value
//!     let new_config = AppConfig {
//!         theme: "dark".to_string(),
//!         auto_save: true,
//!     };
//!     value.set(new_config).await?;
//!
//!     // Delete value
//!     value.remove().await?;
//!
//!     Ok(())
//! }
//! ```

mod handle;
mod key;

pub use handle::{PersistedValue, PersistedValueError, PersistedValueItem, PersistedValueTrait};
pub use key::PersistedValueKey;

/// This code is not meant to be used directly, users of this crate should use the
/// [crate::register_persisted_value] macro to declare their keys.
#[doc(hidden)]
pub mod ___internal {

    // This trait is in an internal module to forbid users from implementing `PersistedValueKey`
    // directly.
    pub trait Internal {}
}
pub(crate) use ___internal::Internal;
