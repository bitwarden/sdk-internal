#[cfg(feature = "internal")]
use bitwarden_crypto::{AsymmetricEncString, EncString};

use super::crypto::{
    derive_key_connector, make_key_pair, verify_asymmetric_keys, DeriveKeyConnectorError,
    DeriveKeyConnectorRequest, EnrollAdminPasswordResetError, MakeKeyPairResponse,
    MobileCryptoError, VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
};
use crate::{client::encryption_settings::EncryptionSettingsError, Client};
#[cfg(feature = "internal")]
use crate::{
    error::Result,
    mobile::crypto::{
        derive_pin_key, derive_pin_user_key, enroll_admin_password_reset, get_user_encryption_key,
        initialize_org_crypto, initialize_user_crypto, update_password, DerivePinKeyResponse,
        InitOrgCryptoRequest, InitUserCryptoRequest, UpdatePasswordResponse,
    },
};

pub struct CryptoClient<'a> {
    pub(crate) client: &'a crate::Client,
}

impl CryptoClient<'_> {
    pub async fn initialize_user_crypto(
        &self,
        req: InitUserCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        initialize_user_crypto(self.client, req).await
    }

    pub async fn initialize_org_crypto(
        &self,
        req: InitOrgCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        initialize_org_crypto(self.client, req).await
    }

    pub async fn get_user_encryption_key(&self) -> Result<String, MobileCryptoError> {
        get_user_encryption_key(self.client).await
    }

    pub fn update_password(
        &self,
        new_password: String,
    ) -> Result<UpdatePasswordResponse, MobileCryptoError> {
        update_password(self.client, new_password)
    }

    pub fn derive_pin_key(&self, pin: String) -> Result<DerivePinKeyResponse, MobileCryptoError> {
        derive_pin_key(self.client, pin)
    }

    pub fn derive_pin_user_key(
        &self,
        encrypted_pin: EncString,
    ) -> Result<EncString, MobileCryptoError> {
        derive_pin_user_key(self.client, encrypted_pin)
    }

    pub fn enroll_admin_password_reset(
        &self,
        public_key: String,
    ) -> Result<AsymmetricEncString, EnrollAdminPasswordResetError> {
        enroll_admin_password_reset(self.client, public_key)
    }

    /// Derive the master key for migrating to the key connector
    pub fn derive_key_connector(
        &self,
        request: DeriveKeyConnectorRequest,
    ) -> Result<String, DeriveKeyConnectorError> {
        derive_key_connector(request)
    }

    pub fn make_key_pair(&self, user_key: String) -> Result<MakeKeyPairResponse> {
        make_key_pair(user_key)
    }

    pub fn verify_asymmetric_keys(
        &self,
        request: VerifyAsymmetricKeysRequest,
    ) -> Result<VerifyAsymmetricKeysResponse> {
        verify_asymmetric_keys(request)
    }
}

impl<'a> Client {
    pub fn crypto(&'a self) -> CryptoClient<'a> {
        CryptoClient { client: self }
    }
}
