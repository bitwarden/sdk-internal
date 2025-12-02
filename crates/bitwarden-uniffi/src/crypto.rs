use bitwarden_core::key_management::crypto::{
    DeriveKeyConnectorRequest, DerivePinKeyResponse, EnrollPinResponse, InitOrgCryptoRequest,
    InitUserCryptoRequest, UpdateKdfResponse, UpdatePasswordResponse,
};
use bitwarden_crypto::{EncString, Kdf, UnsignedSharedKey};
use bitwarden_encoding::B64;

use crate::error::Result;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct CryptoClient(pub(crate) bitwarden_core::key_management::CryptoClient);

#[uniffi::export(async_runtime = "tokio")]
impl CryptoClient {
    /// Initialization method for the user crypto. Needs to be called before any other crypto
    /// operations.
    pub async fn initialize_user_crypto(&self, req: InitUserCryptoRequest) -> Result<()> {
        Ok(self.0.initialize_user_crypto(req).await?)
    }

    /// Initialization method for the organization crypto. Needs to be called after
    /// `initialize_user_crypto` but before any other crypto operations.
    pub async fn initialize_org_crypto(&self, req: InitOrgCryptoRequest) -> Result<()> {
        Ok(self.0.initialize_org_crypto(req).await?)
    }

    /// Get the uses's decrypted encryption key. Note: It's very important
    /// to keep this key safe, as it can be used to decrypt all of the user's data
    pub async fn get_user_encryption_key(&self) -> Result<B64> {
        Ok(self.0.get_user_encryption_key().await?)
    }

    /// Create the data necessary to update the user's password. The user's encryption key is
    /// re-encrypted with the new password. This returns the new encrypted user key and the new
    /// password hash but does not update sdk state.
    pub fn make_update_password(&self, new_password: String) -> Result<UpdatePasswordResponse> {
        Ok(self.0.make_update_password(new_password)?)
    }

    /// Generates a PIN protected user key from the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`.
    pub fn derive_pin_key(&self, pin: String) -> Result<DerivePinKeyResponse> {
        Ok(self.0.derive_pin_key(pin)?)
    }

    /// Derives the pin protected user key from encrypted pin. Used when pin requires master
    /// password on first unlock.
    pub fn derive_pin_user_key(&self, encrypted_pin: EncString) -> Result<EncString> {
        Ok(self.0.derive_pin_user_key(encrypted_pin)?)
    }

    /// Protects the current user key with the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`.
    pub fn enroll_pin(&self, pin: String) -> Result<EnrollPinResponse> {
        Ok(self.0.enroll_pin(pin)?)
    }

    /// Protects the current user key with the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`. The provided pin is encrypted with the user key.
    pub fn enroll_pin_with_encrypted_pin(
        &self,
        encrypted_pin: EncString,
    ) -> Result<EnrollPinResponse> {
        Ok(self
            .0
            .enroll_pin_with_encrypted_pin(encrypted_pin.to_string())?)
    }

    pub fn enroll_admin_password_reset(&self, public_key: B64) -> Result<UnsignedSharedKey> {
        Ok(self.0.enroll_admin_password_reset(public_key)?)
    }

    /// Derive the master key for migrating to the key connector
    pub fn derive_key_connector(&self, request: DeriveKeyConnectorRequest) -> Result<B64> {
        Ok(self.0.derive_key_connector(request)?)
    }

    /// Create the data necessary to update the user's kdf settings. The user's encryption key is
    /// re-encrypted for the password under the new kdf settings. This returns the new encrypted
    /// user key and the new password hash but does not update sdk state.
    pub fn make_update_kdf(&self, password: String, kdf: Kdf) -> Result<UpdateKdfResponse> {
        Ok(self.0.make_update_kdf(password, kdf)?)
    }
}
