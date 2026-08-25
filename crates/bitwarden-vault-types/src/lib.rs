#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod uri_match_type;
pub use uri_match_type::UriMatchType;
