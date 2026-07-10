#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

mod pam_client;

pub use pam_client::{PamClient, PamClientExt};
