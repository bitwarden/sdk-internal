use chrono::{DateTime, Utc};

use crate::{
    generate_totp, generate_totp_cipher_view, CipherListView, TotpError, TotpResponse, VaultClient,
};

impl<'a> VaultClient<'a> {
    /// Generate a TOTP code from a provided key.
    ///
    /// Key can be either:
    /// - A base32 encoded string
    /// - OTP Auth URI
    /// - Steam URI
    pub fn generate_totp(
        &'a self,
        key: String,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse, TotpError> {
        generate_totp(key, time)
    }

    /// Generate a TOTP code from a provided cipher list view.
    pub fn generate_totp_cipher_view(
        &'a self,
        view: CipherListView,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse, TotpError> {
        let key_store = self.client.internal.get_key_store();

        generate_totp_cipher_view(&mut key_store.context(), view, time)
    }
}
