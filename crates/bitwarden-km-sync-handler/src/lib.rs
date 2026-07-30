#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod km_sync_handler;

#[cfg(not(target_arch = "wasm32"))]
pub use km_sync_handler::KmSyncHandler;
pub use km_sync_handler::{
    KmSyncData, KmSyncHandlerClient, KmSyncHandlerClientExt, KmSyncUserDecryption,
};
