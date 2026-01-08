//! Internal setting storage type.

use serde::{Deserialize, Serialize};

/// Internal setting value stored in the settings repository.
///
/// This type wraps a JSON value for flexible storage. Users should not work with
/// this type directly - use [`SettingsRepository`](crate::SettingsRepository) instead,
/// which provides type-safe access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Setting(pub(crate) serde_json::Value);

// Register Setting for repository usage
bitwarden_state::register_repository_item!(Setting, "Setting");
