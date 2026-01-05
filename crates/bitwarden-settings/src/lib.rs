#![doc = include_str!("../README.md")]

mod key;
mod repository;
mod setting;

pub use key::Key;
pub use repository::{ClientSettingsExt, SettingsRepository};
pub use setting::Setting;
