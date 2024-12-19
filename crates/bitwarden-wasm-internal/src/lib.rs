mod client;
mod crypto;
mod custom_types;
mod ssh;
mod vault;

pub use client::BitwardenClient;
pub use crypto::CryptoClient;
pub use vault::{folders::ClientFolders, VaultClient};

#[doc = include_str!("../doc/test.md")]
pub fn test2() {
    println!("Hello, world!");
}
