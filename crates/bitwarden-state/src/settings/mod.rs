//! The old path of the values API. Removed once every caller has migrated to
//! [`crate::values`].

pub use crate::values::{Key, Setting, ValueError as SettingsError, ValueItem as SettingItem};
