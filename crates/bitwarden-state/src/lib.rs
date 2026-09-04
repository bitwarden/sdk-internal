#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// This module provides a generic repository interface for storing and retrieving items.
pub mod repository;

/// This module provides a registry for managing repositories of different types.
pub mod registry;

/// Type-safe settings API for storing application configuration and state.
pub mod settings;

pub(crate) mod persistent_value;
pub(crate) mod sdk_managed;

pub use persistent_value::PersistentValue;
pub use sdk_managed::{DatabaseConfiguration, DatabaseError};
pub use settings::{Key, Setting, SettingItem, SettingTrait, SettingsError};
