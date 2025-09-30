use bitwarden_crypto::{CryptoError, Decryptable, Kdf};
#[cfg(feature = "internal")]
use bitwarden_crypto::{EncString, UnsignedSharedKey};
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::crypto::{
    DeriveKeyConnectorError, DeriveKeyConnectorRequest, EnrollAdminPasswordResetError,
    MakeKeyPairResponse, VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    derive_key_connector, make_key_pair, verify_asymmetric_keys,
};
#[cfg(any(feature = "wasm", test))]
use crate::key_management::PasswordProtectedKeyEnvelope;
#[cfg(feature = "internal")]
use crate::key_management::{
    SymmetricKeyId,
    crypto::{
        DerivePinKeyResponse, InitOrgCryptoRequest, InitUserCryptoRequest, UpdatePasswordResponse,
        derive_pin_key, derive_pin_user_key, enroll_admin_password_reset, get_user_encryption_key,
        initialize_org_crypto, initialize_user_crypto,
    },
};
use crate::{
    Client,
    client::encryption_settings::EncryptionSettingsError,
    error::StatefulCryptoError,
    key_management::crypto::{
        CryptoClientError, EnrollPinResponse, UpdateKdfResponse, UserCryptoV2KeysResponse,
        enroll_pin, get_v2_rotated_account_keys, make_update_kdf, make_update_password,
        make_v2_keys_for_v1_user,
    },
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
    pub fn make_key_pair(&self, user_key: B64) -> Result<MakeKeyPairResponse, CryptoError> {
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

    /// Create the data necessary to update the user's kdf settings. The user's encryption key is
    /// re-encrypted for the password under the new kdf settings. This returns the re-encrypted
    /// user key and the new password hash but does not update sdk state.
    pub fn make_update_kdf(
        &self,
        password: String,
        kdf: Kdf,
    ) -> Result<UpdateKdfResponse, CryptoClientError> {
        make_update_kdf(&self.client, &password, &kdf)
    }

    /// Protects the current user key with the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`.
    pub fn enroll_pin(&self, pin: String) -> Result<EnrollPinResponse, CryptoClientError> {
        enroll_pin(&self.client, pin)
    }

    /// Protects the current user key with the provided PIN. The result can be stored and later
    /// used to initialize another client instance by using the PIN and the PIN key with
    /// `initialize_user_crypto`. The provided pin is encrypted with the user key.
    pub fn enroll_pin_with_encrypted_pin(
        &self,
        // Note: This will be replaced by `EncString` with https://bitwarden.atlassian.net/browse/PM-24775
        encrypted_pin: String,
    ) -> Result<EnrollPinResponse, CryptoClientError> {
        let encrypted_pin: EncString = encrypted_pin.parse()?;
        let pin = encrypted_pin.decrypt(
            &mut self.client.internal.get_key_store().context_mut(),
            SymmetricKeyId::User,
        )?;
        enroll_pin(&self.client, pin)
    }

    /// Decrypts a `PasswordProtectedKeyEnvelope`, returning the user key, if successful.
    /// This is a stop-gap solution, until initialization of the SDK is used.
    #[cfg(any(feature = "wasm", test))]
    pub fn unseal_password_protected_key_envelope(
        &self,
        pin: String,
        envelope: PasswordProtectedKeyEnvelope,
    ) -> Result<Vec<u8>, CryptoClientError> {
        let mut ctx = self.client.internal.get_key_store().context_mut();
        let key_slot = SymmetricKeyId::Local("unseal_password_protected_key_envelope");
        envelope.unseal(key_slot, pin.as_str(), &mut ctx)?;
        #[allow(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(key_slot)?;
        Ok(key.to_encoded().to_vec())
    }
}

impl CryptoClient {
    /// Get the uses's decrypted encryption key. Note: It's very important
    /// to keep this key safe, as it can be used to decrypt all of the user's data
    pub async fn get_user_encryption_key(&self) -> Result<B64, CryptoClientError> {
        get_user_encryption_key(&self.client).await
    }

    /// Create the data necessary to update the user's password. The user's encryption key is
    /// re-encrypted with the new password. This returns the new encrypted user key and the new
    /// password hash but does not update sdk state.
    pub fn make_update_password(
        &self,
        new_password: String,
    ) -> Result<UpdatePasswordResponse, CryptoClientError> {
        make_update_password(&self.client, new_password)
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
        public_key: B64,
    ) -> Result<UnsignedSharedKey, EnrollAdminPasswordResetError> {
        enroll_admin_password_reset(&self.client, public_key)
    }

    /// Derive the master key for migrating to the key connector
    pub fn derive_key_connector(
        &self,
        request: DeriveKeyConnectorRequest,
    ) -> Result<B64, DeriveKeyConnectorError> {
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

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{BitwardenLegacyKeyBytes, SymmetricCryptoKey};

    use super::*;
    use crate::client::test_accounts::test_bitwarden_com_account;

    #[tokio::test]
    async fn test_enroll_pin_envelope() {
        // Initialize a test client with user crypto
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let user_key_initial =
            SymmetricCryptoKey::try_from(client.crypto().get_user_encryption_key().await.unwrap())
                .unwrap();

        // Enroll with a PIN, then re-enroll
        let pin = "1234";
        let enroll_response = client.crypto().enroll_pin(pin.to_string()).unwrap();
        let re_enroll_response = client
            .crypto()
            .enroll_pin_with_encrypted_pin(enroll_response.user_key_encrypted_pin.to_string())
            .unwrap();

        let secret = BitwardenLegacyKeyBytes::from(
            client
                .crypto()
                .unseal_password_protected_key_envelope(
                    pin.to_string(),
                    re_enroll_response.pin_protected_user_key_envelope,
                )
                .unwrap(),
        );
        let user_key_final = SymmetricCryptoKey::try_from(&secret).unwrap();
        assert_eq!(user_key_initial, user_key_final);
    }
}
