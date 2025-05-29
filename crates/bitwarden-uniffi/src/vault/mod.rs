use bitwarden_vault::{CipherListView, TotpResponse};
use chrono::{DateTime, Utc};

use crate::error::{Error, Result};

#[allow(missing_docs)]
pub mod attachments;
#[allow(missing_docs)]
pub mod ciphers;
#[allow(missing_docs)]
pub mod collections;
#[allow(missing_docs)]
pub mod folders;
#[allow(missing_docs)]
pub mod password_history;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct VaultClient(pub(crate) bitwarden_vault::VaultClient);

#[uniffi::export]
impl VaultClient {
    /// Folder operations
    pub fn folders(&self) -> folders::FoldersClient {
        folders::FoldersClient(self.0.folders())
    }

    /// Collections operations
    pub fn collections(&self) -> collections::CollectionsClient {
        collections::CollectionsClient(self.0.collections())
    }

    /// Ciphers operations
    pub fn ciphers(&self) -> ciphers::CiphersClient {
        ciphers::CiphersClient(self.0.ciphers())
    }

    /// Password history operations
    pub fn password_history(&self) -> password_history::PasswordHistoryClient {
        password_history::PasswordHistoryClient(self.0.password_history())
    }

    /// Attachment file operations
    pub fn attachments(&self) -> attachments::AttachmentsClient {
        attachments::AttachmentsClient(self.0.attachments())
    }

    /// Generate a TOTP code from a provided key.
    ///
    /// The key can be either:
    /// - A base32 encoded string
    /// - OTP Auth URI
    /// - Steam URI
    pub fn generate_totp(&self, key: String, time: Option<DateTime<Utc>>) -> Result<TotpResponse> {
        Ok(self
            .0
            .totp()
            .generate_totp(key, time)
            .map_err(Error::Totp)?)
    }

    /// Generate a TOTP code from a provided cipher list view.
    pub fn generate_totp_cipher_view(
        &self,
        view: CipherListView,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse> {
        Ok(self
            .0
            .totp()
            .generate_totp_cipher_view(view, time)
            .map_err(Error::Totp)?)
    }
}
