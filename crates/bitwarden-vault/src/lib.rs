#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod cipher;
pub use cipher::*;
mod collection;
pub use collection::{Collection, CollectionView};
mod folder;
pub use folder::{Folder, FolderView};
mod password_history;
pub use password_history::{PasswordHistory, PasswordHistoryView};
mod domain;
pub use domain::GlobalDomains;
mod totp;
pub use totp::{
    generate_totp, generate_totp_cipher_view, Totp, TotpAlgorithm, TotpError, TotpResponse,
};
mod error;
pub use error::{DecryptError, EncryptError, VaultParseError};
mod vault_client;
pub use vault_client::{VaultClient, VaultClientExt};
mod mobile;
pub use mobile::{
    attachment_client::{ClientAttachments, DecryptFileError, EncryptFileError},
    cipher_client::ClientCiphers,
    collection_client::ClientCollections,
    folder_client::ClientFolders,
    password_history_client::ClientPasswordHistory,
};

mod sync;
mod totp_client;
pub use sync::{SyncRequest, SyncResponse};
