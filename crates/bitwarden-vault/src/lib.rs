#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod cipher;
pub use cipher::*;
mod folder;
pub use folder::*;
mod password_history;
pub use password_history::{PasswordHistory, PasswordHistoryView};
mod password_history_client;
pub use password_history_client::PasswordHistoryClient;
mod domain;
pub use domain::GlobalDomains;
mod totp;
pub use totp::{
    Totp, TotpAlgorithm, TotpError, TotpResponse, generate_totp, generate_totp_cipher_view,
};
mod error;
pub use error::{DecryptError, EncryptError, VaultParseError};
mod vault_client;
pub use vault_client::{VaultClient, VaultClientExt};

mod sync;
pub use sync::{SyncRequest, SyncResponse};

#[allow(missing_docs)]
pub mod collection_client;
mod totp_client;

pub use totp_client::TotpClient;
