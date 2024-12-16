use bitwarden_core::{Client, Error};
use bitwarden_crypto::{KeyDecryptable, KeyEncryptable};

use crate::{PasswordHistory, PasswordHistoryView, VaultClient};

pub struct ClientPasswordHistory<'a> {
    pub(crate) client: &'a Client,
}

impl ClientPasswordHistory<'_> {
    pub fn encrypt(&self, history_view: PasswordHistoryView) -> Result<PasswordHistory, Error> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = enc.get_key(&None)?;

        let history = history_view.encrypt_with_key(key)?;

        Ok(history)
    }

    pub fn decrypt_list(
        &self,
        history: Vec<PasswordHistory>,
    ) -> Result<Vec<PasswordHistoryView>, Error> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = enc.get_key(&None)?;

        let history_view = history.decrypt_with_key(key)?;

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
