use bitwarden_core::auth::{
    AuthRequestResponse, KeyConnectorResponse, RegisterKeyResponse, RegisterTdeKeyResponse,
    password::MasterPasswordPolicyOptions,
};
use bitwarden_crypto::{EncString, HashPurpose, Kdf, TrustDeviceResponse, UnsignedSharedKey};
use bitwarden_encoding::B64;

use crate::error::Result;

#[derive(uniffi::Object)]
pub struct AuthClient(pub(crate) bitwarden_core::Client);

#[uniffi::export(async_runtime = "tokio")]
impl AuthClient {
    /// Calculate Password Strength
    pub fn password_strength(
        &self,
        password: String,
        email: String,
        additional_inputs: Vec<String>,
    ) -> u8 {
        self.0
            .auth()
            .password_strength(password, email, additional_inputs)
    }

    /// Evaluate if the provided password satisfies the provided policy
    pub fn satisfies_policy(
        &self,
        password: String,
        strength: u8,
        policy: MasterPasswordPolicyOptions,
    ) -> bool {
        self.0.auth().satisfies_policy(password, strength, &policy)
    }

    /// Hash the user password
    pub async fn hash_password(
        &self,
        email: String,
        password: String,
        kdf_params: Kdf,
        purpose: HashPurpose,
    ) -> Result<B64> {
        Ok(self
            .0
            .kdf()
            .hash_password(email, password, kdf_params, purpose)
            .await?)
    }

    /// Generate keys needed for registration process
    pub fn make_register_keys(
        &self,
        email: String,
        password: String,
        kdf: Kdf,
    ) -> Result<RegisterKeyResponse> {
        Ok(self.0.auth().make_register_keys(email, password, kdf)?)
    }

    /// Generate keys needed for TDE process
    pub fn make_register_tde_keys(
        &self,
        email: String,
        org_public_key: B64,
        remember_device: bool,
    ) -> Result<RegisterTdeKeyResponse> {
        Ok(self
            .0
            .auth()
            .make_register_tde_keys(email, org_public_key, remember_device)?)
    }

    /// Generate keys needed to onboard a new user without master key to key connector
    pub fn make_key_connector_keys(&self) -> Result<KeyConnectorResponse> {
        Ok(self.0.auth().make_key_connector_keys()?)
    }

    /// Validate the user password
    ///
    /// To retrieve the user's password hash, use [`AuthClient::hash_password`] with
    /// `HashPurpose::LocalAuthentication` during login and persist it. If the login method has no
    /// password, use the email OTP.
    pub fn validate_password(&self, password: String, password_hash: B64) -> Result<bool> {
        Ok(self.0.auth().validate_password(password, password_hash)?)
    }

    /// Validate the user password without knowing the password hash
    ///
    /// Used for accounts that we know have master passwords but that have not logged in with a
    /// password. Some example are login with device or TDE.
    ///
    /// This works by comparing the provided password against the encrypted user key.
    pub fn validate_password_user_key(
        &self,
        password: String,
        encrypted_user_key: String,
    ) -> Result<B64> {
        Ok(self
            .0
            .auth()
            .validate_password_user_key(password, encrypted_user_key)?)
    }

    /// Validate the user PIN
    ///
    /// To validate the user PIN, you need to have the user's pin_protected_user_key. This key is
    /// obtained when enabling PIN unlock on the account with the `derive_pin_key` method.
    ///
    /// This works by comparing the decrypted user key with the current user key, so the client must
    /// be unlocked.
    pub fn validate_pin(&self, pin: String, pin_protected_user_key: EncString) -> Result<bool> {
        Ok(self.0.auth().validate_pin(pin, pin_protected_user_key)?)
    }

    /// Initialize a new auth request
    pub fn new_auth_request(&self, email: String) -> Result<AuthRequestResponse> {
        Ok(self.0.auth().new_auth_request(&email)?)
    }

    /// Approve an auth request
    pub fn approve_auth_request(&self, public_key: B64) -> Result<UnsignedSharedKey> {
        Ok(self.0.auth().approve_auth_request(public_key)?)
    }

    /// Trust the current device
    pub fn trust_device(&self) -> Result<TrustDeviceResponse> {
        Ok(self.0.auth().trust_device()?)
    }
}
