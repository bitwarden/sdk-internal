#![doc = include_str!("../README.md")]

pub use invite::{Invite, InviteKeyBundleError, InviteSecret};
mod invite;

#[cfg(feature = "wasm")]
pub mod wasm;
