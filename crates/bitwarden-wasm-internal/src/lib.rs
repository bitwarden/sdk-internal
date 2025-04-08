#![doc = include_str!("../README.md")]
// We define the WASM API as async so that we can use the same API for the IPC remote API.
// This means that some methods will need to be async even though they do no async work.
#![allow(clippy::unused_async)]

mod client;
mod crypto;
mod custom_types;
mod init;
mod pure_crypto;
mod ssh;
mod vault;

pub use bitwarden_ipc::wasm::*;
pub use client::BitwardenClient;
pub use crypto::CryptoClient;
pub use init::init_sdk;
pub use vault::{folders::ClientFolders, VaultClient};
