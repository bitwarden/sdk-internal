use bitwarden_vault::{CipherListView, TotpResponse};
use chrono::{DateTime, Utc};

use crate::error::{Error, Result};

pub mod attachments;
pub mod ciphers;
pub mod collections;
pub mod folders;
pub mod password_history;

#[derive(uniffi::Object)]
pub struct VaultClient(pub(crate) bitwarden_vault::VaultClient);

#[uniffi::export]
impl VaultClient {
    /// Folder operations
    pub fn folders(&self) -> folders::ClientFolders {
        folders::ClientFolders(self.0.folders())
    }

    /// Collections operations
    pub fn collections(&self) -> collections::ClientCollections {
        collections::ClientCollections(self.0.collections())
    }

    /// Ciphers operations
    pub fn ciphers(&self) -> ciphers::ClientCiphers {
        ciphers::ClientCiphers(self.0.ciphers())
    }

    /// Password history operations
    pub fn password_history(&self) -> password_history::ClientPasswordHistory {
        password_history::ClientPasswordHistory(self.0.password_history())
    }

    /// Attachment file operations
    pub fn attachments(&self) -> attachments::ClientAttachments {
        attachments::ClientAttachments(self.0.attachments())
    }

    /// Generate a TOTP code from a provided key.
    ///
    /// The key can be either:
    /// - A base32 encoded string
    /// - OTP Auth URI
    /// - Steam URI
    pub fn generate_totp(&self, key: String, time: Option<DateTime<Utc>>) -> Result<TotpResponse> {
        Ok(self.0.generate_totp(key, time).map_err(Error::Totp)?)
    }

    /// Generate a TOTP code from a provided cipher list view.
    pub fn generate_totp_cipher_view(
        &self,
        view: CipherListView,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse> {
        Ok(self
            .0
            .generate_totp_cipher_view(view, time)
            .map_err(Error::Totp)?)
    }
}
