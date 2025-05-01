use chrono::{DateTime, Utc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TotpClient(bitwarden_vault::VaultClient);

impl TotpClient {
    pub fn new(client: bitwarden_vault::VaultClient) -> Self {
        Self(client)
    }
}

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
    ///
    /// # Returns
    /// - `Ok(TotpResponse)` containing the generated code and period
    /// - `Err(TotpError)` if code generation fails
    pub fn generate_totp(
        &self,
        key: String,
        time_ms: Option<f64>,
    ) -> Result<bitwarden_vault::TotpResponse, bitwarden_vault::TotpError> {
        let datetime = time_ms.and_then(|time| DateTime::<Utc>::from_timestamp_millis(time as i64));

        self.0.generate_totp(key, datetime)
    }
}
