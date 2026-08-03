#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod crypto_sync_handler;

pub use crypto_sync_handler::{
    CryptoSyncData, CryptoSyncHandlerClient, CryptoSyncHandlerClientExt, CryptoSyncUserDecryption,
};
#[cfg(not(target_arch = "wasm32"))]
pub use crypto_sync_handler::{CryptoSyncDataParseError, CryptoSyncHandler};
