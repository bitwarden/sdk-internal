#![doc = include_str!("../README.md")]

pub use invite::{Invite, InviteSecret, InviteKeyBundleError};
mod invite;

#[cfg(feature = "wasm")]
pub mod wasm;
