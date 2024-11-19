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
pub use totp::{generate_totp, generate_totp_cipher_view, TotpError, TotpResponse};
mod error;
pub use error::VaultParseError;
mod vault_client;
pub use vault_client::{VaultClient, VaultClientExt};
mod mobile;
mod sync;
mod totp_client;
pub use sync::{SyncRequest, SyncResponse};
