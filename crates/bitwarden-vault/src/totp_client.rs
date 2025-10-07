use bitwarden_core::Client;
use chrono::{DateTime, Utc};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CipherListView, TotpError, TotpResponse, generate_totp, generate_totp_cipher_view};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct TotpClient {
    pub(crate) client: Client,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl TotpClient {
    /// Generates a TOTP code from a provided key
    ///
    /// # Arguments
    /// - `key` - Can be:
    ///     - A base32 encoded string
    ///     - OTP Auth URI
    ///     - Steam URI
    /// - `time_ms` - Optional timestamp in milliseconds
    #[wasm_bindgen(js_name = "generate_totp")]
    pub fn generate_totp_wasm(
        &self,
        key: String,
        time_ms: Option<f64>,
    ) -> Result<TotpResponse, TotpError> {
        let datetime = time_ms.and_then(|time| DateTime::<Utc>::from_timestamp_millis(time as i64));

        self.generate_totp(key, datetime)
    }
}

impl TotpClient {
    /// Generate a TOTP code from a provided key.
    ///
    /// Key can be either:
    /// - A base32 encoded string
    /// - OTP Auth URI
    /// - Steam URI
    pub fn generate_totp(
        &self,
        key: String,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse, TotpError> {
        generate_totp(key, time)
    }

    /// Generate a TOTP code from a provided cipher list view.
    pub fn generate_totp_cipher_view(
        &self,
        view: CipherListView,
        time: Option<DateTime<Utc>>,
    ) -> Result<TotpResponse, TotpError> {
        let key_store = self.client.internal.get_key_store();

        generate_totp_cipher_view(&mut key_store.context(), view, time)
    }
}
