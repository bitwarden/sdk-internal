#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod locking_client;
mod session_key;

pub use locking_client::{LockingClient, LockingClientExt, LockingError, UnlockMethod};
pub use session_key::SessionKey;
