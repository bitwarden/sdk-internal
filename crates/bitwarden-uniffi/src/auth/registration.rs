use bitwarden_auth::{
    AuthClientExt,
    registration::{
        JitMasterPasswordRegistrationRequest, JitMasterPasswordRegistrationResponse,
        KeyConnectorRegistrationResult, TdeRegistrationRequest, TdeRegistrationResponse,
    },
};

use crate::error::BitwardenError;

#[derive(uniffi::Object)]
pub struct RegistrationClient(pub(crate) bitwarden_core::Client);

#[uniffi::export(async_runtime = "tokio")]
impl RegistrationClient {
    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls in
    /// admin password reset and finally enrolls the user to TDE unlock.
    pub async fn post_keys_for_tde_registration(
        &self,
        request: TdeRegistrationRequest,
    ) -> Result<TdeRegistrationResponse, BitwardenError> {
        Ok(self
            .0
            .auth_new()
            .registration()
            .post_keys_for_tde_registration(request)
            .await?)
    }

    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls the
    /// user to key connector unlock.
    pub async fn post_keys_for_key_connector_registration(
        &self,
        key_connector_url: String,
        sso_org_identifier: String,
    ) -> Result<KeyConnectorRegistrationResult, BitwardenError> {
        Ok(self
            .0
            .auth_new()
            .registration()
            .post_keys_for_key_connector_registration(key_connector_url, sso_org_identifier)
            .await?)
    }

    /// Initializes a new cryptographic state for a user and posts it to the server;
    /// enrolls the user to master password unlock.
    pub async fn post_keys_for_jit_password_registration(
        &self,
        request: JitMasterPasswordRegistrationRequest,
    ) -> Result<JitMasterPasswordRegistrationResponse, BitwardenError> {
        Ok(self
            .0
            .auth_new()
            .registration()
            .post_keys_for_jit_password_registration(request)
            .await?)
    }
}
