use bitwarden_core::Client;

use crate::{DecryptError, EncryptError, PasswordHistory, PasswordHistoryView};

#[allow(missing_docs)]
pub struct PasswordHistoryClient {
    pub(crate) client: Client,
}

impl PasswordHistoryClient {
    #[allow(missing_docs)]
    pub fn encrypt(
        &self,
        history_view: PasswordHistoryView,
    ) -> Result<PasswordHistory, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let history = key_store.encrypt(history_view)?;
        Ok(history)
    }

    #[allow(missing_docs)]
    pub fn decrypt_list(
        &self,
        history: Vec<PasswordHistory>,
    ) -> Result<Vec<PasswordHistoryView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let history_view = key_store.decrypt_list(&history)?;
        Ok(history_view)
    }
}
