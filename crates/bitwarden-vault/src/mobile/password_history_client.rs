use bitwarden_core::Client;

use crate::{DecryptError, EncryptError, PasswordHistory, PasswordHistoryView, VaultClient};

pub struct ClientPasswordHistory<'a> {
    pub(crate) client: &'a Client,
}

impl ClientPasswordHistory<'_> {
    pub fn encrypt(
        &self,
        history_view: PasswordHistoryView,
    ) -> Result<PasswordHistory, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let history = key_store.encrypt(history_view)?;
        Ok(history)
    }

    pub fn decrypt_list(
        &self,
        history: Vec<PasswordHistory>,
    ) -> Result<Vec<PasswordHistoryView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let history_view = key_store.decrypt_list(&history)?;
        Ok(history_view)
    }
}

impl<'a> VaultClient<'a> {
    pub fn password_history(&'a self) -> ClientPasswordHistory<'a> {
        ClientPasswordHistory {
            client: self.client,
        }
    }
}
