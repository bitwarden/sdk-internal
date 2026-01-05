//! # Bitwarden Settings
//!
//! Type-safe settings repository for storing application configuration and state.
//!
//! This crate provides a high-level API for storing and retrieving typed settings using
//! compile-time type-safe keys backed by the SDK's repository pattern with SQLite.
//!
//! ## Architecture
//!
//! - **Storage**: SQLite database using SDK's repository pattern
//! - **Type Safety**: Compile-time type-safe keys prevent type mismatches
//! - **Serialization**: Automatic JSON serialization/deserialization
//! - **Error Handling**: Graceful degradation on deserialization errors
//!
//! ## Usage
//!
//! ```rust,no_run
//! use bitwarden_settings::{ClientSettingsExt, Key};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct MyConfig {
//!     theme: String,
//!     auto_save: bool,
//! }
//!
//! const CONFIG: Key<MyConfig> = Key::new("my_config");
//!
//! // In async context:
//! # async {
//! # let client: bitwarden_core::Client = todo!();
//! // Get setting
//! let config: Option<MyConfig> = client.settings().get(CONFIG).await?;
//!
//! // Set setting
//! let new_config = MyConfig {
//!     theme: "dark".to_string(),
//!     auto_save: true,
//! };
//! client.settings().set(CONFIG, new_config).await?;
//!
//! // Remove setting
//! client.settings().remove(CONFIG).await?;
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! # };
//! ```

mod key;
mod repository;
mod setting;

use bitwarden_state::repository::RepositoryMigrationStep;
pub use key::Key;
pub use repository::{ClientSettingsExt, SettingsRepository};
pub use setting::Setting;

/// Get the migration step for the Setting repository item.
///
/// This should be included in the application's migration list when initializing
/// the database to ensure the settings table is created.
pub fn get_settings_migration_step() -> RepositoryMigrationStep {
    Setting::migration_step()
}
