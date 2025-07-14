use bitwarden_crypto::CryptoError;
#[cfg(feature = "internal")]
use bitwarden_crypto::{EncString, UnsignedSharedKey};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::crypto::{
    derive_key_connector, make_key_pair, verify_asymmetric_keys, DeriveKeyConnectorError,
    DeriveKeyConnectorRequest, EnrollAdminPasswordResetError, MakeKeyPairResponse,
    VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
};
#[cfg(feature = "internal")]
use crate::key_management::crypto::{
    derive_pin_key, derive_pin_user_key, enroll_admin_password_reset, get_user_encryption_key,
    initialize_org_crypto, initialize_user_crypto, update_password, DerivePinKeyResponse,
    InitOrgCryptoRequest, InitUserCryptoRequest, UpdatePasswordResponse,
};
use crate::{
    client::encryption_settings::EncryptionSettingsError,
    error::StatefulCryptoError,
    key_management::crypto::{
        get_v2_rotated_account_keys, make_v2_keys_for_v1_user, CryptoClientError,
        UserCryptoV2KeysResponse,
    },
    Client,
};

/// A client for the crypto operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CryptoClient {
    pub(crate) client: crate::Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CryptoClient {
    /// Initialization method for the user crypto. Needs to be called before any other crypto
    /// operations.
    pub async fn initialize_user_crypto(
        &self,
        req: InitUserCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        initialize_user_crypto(&self.client, req).await
    }

    /// Initialization method for the organization crypto. Needs to be called after
    /// `initialize_user_crypto` but before any other crypto operations.
    pub async fn initialize_org_crypto(
        &self,
        req: InitOrgCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        initialize_org_crypto(&self.client, req).await
    }

    /// Generates a new key pair and encrypts the private key with the provided user key.
    /// Crypto initialization not required.
    pub fn make_key_pair(&self, user_key: String) -> Result<MakeKeyPairResponse, CryptoError> {
        make_key_pair(user_key)
    }

    /// Verifies a user's asymmetric keys by decrypting the private key with the provided user
    /// key. Returns if the private key is decryptable and if it is a valid matching key.
    /// Crypto initialization not required.
    pub fn verify_asymmetric_keys(
        &self,
        request: VerifyAsymmetricKeysRequest,
    ) -> Result<VerifyAsymmetricKeysResponse, CryptoError> {
        verify_asymmetric_keys(request)
    }

    /// Makes a new signing key pair and signs the public key for the user
    pub fn make_keys_for_user_crypto_v2(
        &self,
    ) -> Result<UserCryptoV2KeysResponse, StatefulCryptoError> {
        make_v2_keys_for_v1_user(&self.client)
    }

    /// Creates a rotated set of account keys for the current state
    pub fn get_v2_rotated_account_keys(
        &self,
    ) -> Result<UserCryptoV2KeysResponse, StatefulCryptoError> {
        get_v2_rotated_account_keys(&self.client)
    }
}

impl CryptoClient {
    /// Get the uses's decrypted encryption key. Note: It's very important
    /// to keep this key safe, as it can be used to decrypt all of the user's data
    pub async fn get_user_encryption_key(&self) -> Result<String, CryptoClientError> {
        get_user_encryption_key(&self.client).await
    }

    /// Update the user's password, which will re-encrypt the user's encryption key with the new
    /// password. This returns the new encrypted user key and the new password hash.
    pub fn update_password(
        &self,
        new_password: String,
    ) -> Result<UpdatePasswordResponse, CryptoClientError> {
        update_password(&self.client, new_password)
    }

    /// Generates a PIN protected user key from the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`.
    pub fn derive_pin_key(&self, pin: String) -> Result<DerivePinKeyResponse, CryptoClientError> {
        derive_pin_key(&self.client, pin)
    }

    /// Derives the pin protected user key from encrypted pin. Used when pin requires master
    /// password on first unlock.
    pub fn derive_pin_user_key(
        &self,
        encrypted_pin: EncString,
    ) -> Result<EncString, CryptoClientError> {
        derive_pin_user_key(&self.client, encrypted_pin)
    }

    /// Prepares the account for being enrolled in the admin password reset feature. This encrypts
    /// the users [UserKey][bitwarden_crypto::UserKey] with the organization's public key.
    pub fn enroll_admin_password_reset(
        &self,
        public_key: String,
    ) -> Result<UnsignedSharedKey, EnrollAdminPasswordResetError> {
        enroll_admin_password_reset(&self.client, public_key)
    }

    /// Derive the master key for migrating to the key connector
    pub fn derive_key_connector(
        &self,
        request: DeriveKeyConnectorRequest,
    ) -> Result<String, DeriveKeyConnectorError> {
        derive_key_connector(request)
    }
}

impl Client {
    /// Access to crypto functionality.
    pub fn crypto(&self) -> CryptoClient {
        CryptoClient {
            client: self.clone(),
        }
    }
}
