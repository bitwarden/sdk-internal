//! Type-safe access to individual stored values.
//!
//! A value is a named singleton the SDK reads and writes by itself — the active user's id, the
//! last sync timestamp, feature flags. Repositories, by contrast, hold collections keyed by id.
//!
//! # Usage
//!
//! ```rust,ignore
//! use bitwarden_state::register_value_key;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct AppConfig {
//!     theme: String,
//!     auto_save: bool,
//! }
//!
//! register_value_key!(pub CONFIG: AppConfig = "app_config");
//!
//! async fn example(client: &bitwarden_core::Client) -> Result<(), Box<dyn std::error::Error>> {
//!     let config = client.platform().state().value::<CONFIG>();
//!
//!     // Read, erroring if the value has never been written
//!     let current: AppConfig = config.get().await?;
//!
//!     // Read, treating absence as an expected outcome
//!     let current: Option<AppConfig> = config.get_opt().await?;
//!
//!     config
//!         .set(AppConfig {
//!             theme: "dark".to_string(),
//!             auto_save: true,
//!         })
//!         .await?;
//!
//!     config.remove().await?;
//!
//!     Ok(())
//! }
//! ```

mod key;
mod setting;
mod value;

pub use key::{Key, ValueKey};
pub use setting::Setting;
pub use value::{Value, ValueError, ValueItem};

/// This code is not meant to be used directly, users of this crate should use the
/// [crate::register_value_key] macro to declare their keys.
#[doc(hidden)]
pub mod ___internal {

    // This trait is in an internal module to forbid users from implementing `ValueKey` directly.
    pub trait Internal {}
}
pub(crate) use ___internal::Internal;
