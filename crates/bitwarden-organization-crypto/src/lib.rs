#![doc = include_str!("../README.md")]

mod invite_key_bundle;
pub use invite_key_bundle::{Invite, InviteBundle, InviteKeyBundleError, InviteKeyData};
pub mod invite;

#[cfg(feature = "wasm")]
pub mod wasm;
