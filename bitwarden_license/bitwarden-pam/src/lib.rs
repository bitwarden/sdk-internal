#![doc = include_str!("../README.md")]

mod pam_client;

pub use pam_client::{PamClient, PamClientExt};
