use bitwarden_vault::{PasswordHistory, PasswordHistoryView};

use crate::Result;

#[expect(missing_docs)]
#[derive(uniffi::Object)]
pub struct PasswordHistoryClient(pub(crate) bitwarden_vault::PasswordHistoryClient);

#[uniffi::export]
impl PasswordHistoryClient {
    /// Encrypt password history
    pub fn encrypt(&self, password_history: PasswordHistoryView) -> Result<PasswordHistory> {
        Ok(self.0.encrypt(password_history)?)
    }

    /// Decrypt password history
    pub fn decrypt_list(&self, list: Vec<PasswordHistory>) -> Result<Vec<PasswordHistoryView>> {
        Ok(self.0.decrypt_list(list)?)
    }
}
