#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// This module provides a generic repository interface for storing and retrieving items.
pub mod repository;

/// This module provides a registry for managing repositories of different types.
pub mod registry;

/// Type-safe storage for individual named values, such as the active user or the last sync time.
pub mod values;

/// The old path of [`values`]. Removed once every caller has migrated.
pub mod settings;

pub(crate) mod sdk_managed;

pub use repository::handle::Repository;
pub use sdk_managed::{DatabaseConfiguration, DatabaseError};
pub use values::{Value, ValueError, ValueItem, ValueKey};
/// The old names of the values API. Removed once every caller has migrated.
pub use values::{Key, Setting, ValueError as SettingsError, ValueItem as SettingItem};
