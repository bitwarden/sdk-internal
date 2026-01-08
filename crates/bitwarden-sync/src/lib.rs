#![doc = include_str!("../README.md")]

mod events;
mod sync_client;

pub use events::{SyncEventHandler, SyncEventRegistry, SyncHandlerError};
pub use sync_client::{SyncClient, SyncClientExt, SyncError, SyncRequest};
