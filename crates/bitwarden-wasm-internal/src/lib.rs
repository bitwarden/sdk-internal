#![doc = include_str!("../README.md")]

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
pub use vault::{folders::FoldersClient, VaultClient};
