//! Type-safe settings repository for storing application configuration and state.
//!
//! This module provides a type-safe key-value API for storing settings, backed by
//! the SDK's repository pattern.
//!
//! # Usage
//!
//! ```rust,ignore
//! use bitwarden_state::register_setting_key;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct AppConfig {
//!     theme: String,
//!     auto_save: bool,
//! }
//!
//! // Register a type-safe key
//! register_setting_key!(const CONFIG: AppConfig = "app_config");
//!
//! // Access settings via client.platform().state().setting()
//! async fn example(client: &bitwarden_core::Client) -> Result<(), Box<dyn std::error::Error>> {
//!     // Get a setting handle
//!     let setting = client.platform().state().setting(CONFIG)?;
//!
//!     // Get value
//!     let config: Option<AppConfig> = setting.get().await?;
//!
//!     // Update value
//!     let new_config = AppConfig {
//!         theme: "dark".to_string(),
//!         auto_save: true,
//!     };
//!     setting.update(new_config).await?;
//!
//!     // Delete setting
//!     setting.delete().await?;
//!
//!     Ok(())
//! }
//! ```

mod key;
mod setting;

pub use key::Key;
pub use setting::{Setting, SettingItem, SettingsError};
