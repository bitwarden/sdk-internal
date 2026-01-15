#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// This module provides a generic repository interface for storing and retrieving items.
pub mod repository;

/// This module provides a registry for managing repositories of different types.
pub mod registry;

/// Type-safe settings repository for storing application configuration and state.
pub mod settings;

pub(crate) mod sdk_managed;

pub use sdk_managed::DatabaseConfiguration;
pub use settings::{Key, Setting, SettingItem, SettingsError};
