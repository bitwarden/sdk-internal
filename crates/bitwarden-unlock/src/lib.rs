#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod session_key;
mod unlock_client;

pub use session_key::SessionKey;
pub use unlock_client::{UnlockClient, UnlockClientExt, UnlockError, UnlockMethod};
