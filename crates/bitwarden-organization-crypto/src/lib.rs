#![doc = include_str!("../README.md")]

mod invite_key_bundle;
pub use invite_key_bundle::{
    InviteBundle, InviteKeyBundleError, InviteKeyData, Invite,
};

#[cfg(feature = "wasm")]
pub mod wasm;
