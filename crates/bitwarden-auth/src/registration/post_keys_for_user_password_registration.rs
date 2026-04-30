//! Initializes new password-based cryptographic state for a user
//! and posts the state to the server
use bitwarden_api_identity::models::RegisterFinishRequestModel;
use bitwarden_core::{
    OrganizationId, UserId,
    key_management::{
        MasterPasswordUnlockData, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_encoding::B64;
use tracing::error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::registration::{RegistrationClient, RegistrationError};

/// Request parameters for master password registration
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct UserMasterPasswordRegistrationRequest {
    /// Email for the account being initialized
    pub email: String,
    /// Salt for master password hashing
    pub salt: String,
    /// Master password for the account
    pub master_password: String,
    /// Optional hint for the master password
    pub master_password_hint: Option<String>,
    /// Optional token for email verification
    pub email_verification_token: Option<String>,
    /// Optional organization user ID for organization invitations
    pub organization_user_id: Option<OrganizationId>,
    /// Optional organization invite token for joining an organization
    pub org_invite_token: Option<String>,
    /// Optional token for sponsored free family plan
    pub org_sponsored_free_family_plan_token: Option<String>,
    /// Optional token for accepting emergency access invitation
    pub accept_emergency_access_invite_token: Option<String>,
    /// Optional emergency access ID for accepting emergency access invitation
    pub accept_emergency_access_id: Option<UserId>,
    /// Optional provider invite token for joining as a provider
    pub provider_invite_token: Option<String>,
    /// Optional provider user ID for provider invitations
    pub provider_user_id: Option<UserId>,
}

/// Result of user master password registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct UserMasterPasswordRegistrationResponse {
    /// The account cryptographic state of the user
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The master password unlock data
    pub master_password_unlock: MasterPasswordUnlockData,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: B64,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Initializes new password-based cryptographic state for a user
    /// and posts the state to the server
    pub async fn post_keys_for_user_password_registration(
        &self,
        request: UserMasterPasswordRegistrationRequest,
    ) -> Result<UserMasterPasswordRegistrationResponse, RegistrationError> {
        let client = &self.client.internal;
        let identity_client = &client.get_api_configurations().identity_client;
        internal_post_keys_for_user_password_registration(self, identity_client, request).await
    }
}

async fn internal_post_keys_for_user_password_registration(
    registration_client: &RegistrationClient,
    identity_client: &bitwarden_api_identity::apis::ApiClient,
    request: UserMasterPasswordRegistrationRequest,
) -> Result<UserMasterPasswordRegistrationResponse, RegistrationError> {
    let make_crypto_response = registration_client
        .client
        .crypto()
        .make_user_password_registration(request.master_password, request.salt)
        .map_err(|_| RegistrationError::Crypto)?;
    let account_keys = Some(Box::new(
        internal_account_keys_from_api_model(&make_crypto_response.account_keys_request)
            .map_err(|_| RegistrationError::Crypto)?,
    ));

    let api_request = RegisterFinishRequestModel {
        email: Some(request.email),
        master_password_hint: request.master_password_hint,
        master_password_unlock: Some(Box::new(
            (&make_crypto_response.master_password_unlock_data).into(),
        )),
        master_password_authentication: Some(Box::new(
            (&make_crypto_response.master_password_authentication_data).into(),
        )),
        account_keys,
        email_verification_token: request.email_verification_token,
        organization_user_id: request.organization_user_id.map(Into::into),
        org_invite_token: (request.org_invite_token),
        org_sponsored_free_family_plan_token: (request.org_sponsored_free_family_plan_token),
        accept_emergency_access_invite_token: (request.accept_emergency_access_invite_token),
        accept_emergency_access_id: request.accept_emergency_access_id.map(Into::into),
        provider_invite_token: (request.provider_invite_token),
        provider_user_id: request.provider_user_id.map(Into::into),
        // TODO remove deprecated fields below with https://bitwarden.atlassian.net/browse/PM-27326
        kdf: None,
        kdf_memory: None,
        kdf_parallelism: None,
        kdf_iterations: None,
        master_password_hash: None,
        user_symmetric_key: None,
        user_asymmetric_keys: None,
    };

    identity_client
        .accounts_api()
        .post_register_finish(Some(api_request))
        .await
        .map_err(|e| {
            error!("Failed to post account keys: {e:?}");
            RegistrationError::Api
        })?;

    Ok(UserMasterPasswordRegistrationResponse {
        account_cryptographic_state: make_crypto_response.account_cryptographic_state,
        master_password_unlock: make_crypto_response.master_password_unlock_data,
        user_key: make_crypto_response.user_key.to_encoded().to_vec().into(),
    })
}

fn internal_account_keys_from_api_model(
    input_model: &bitwarden_api_api::models::AccountKeysRequestModel,
) -> Result<bitwarden_api_identity::models::AccountKeysRequestModel, RegistrationError> {
    let public_key_encryption_key_pair =
        input_model
            .public_key_encryption_key_pair
            .as_deref()
            .map(|pair| {
                Box::new(
                    bitwarden_api_identity::models::PublicKeyEncryptionKeyPairRequestModel {
                        wrapped_private_key: pair.wrapped_private_key.clone(),
                        public_key: pair.public_key.clone(),
                        signed_public_key: pair.signed_public_key.clone(),
                    },
                )
            });

    let signature_key_pair = input_model.signature_key_pair.as_deref().map(|pair| {
        Box::new(
            bitwarden_api_identity::models::SignatureKeyPairRequestModel {
                signature_algorithm: pair.signature_algorithm.clone(),
                wrapped_signing_key: pair.wrapped_signing_key.clone(),
                verifying_key: pair.verifying_key.clone(),
            },
        )
    });

    let security_state = input_model.security_state.as_deref().map(|state| {
        Box::new(bitwarden_api_identity::models::SecurityStateModel {
            security_state: state.security_state.clone(),
            security_version: state.security_version,
        })
    });

    let user_key_encrypted_account_private_key =
        input_model.user_key_encrypted_account_private_key.clone();

    let account_public_key = input_model.account_public_key.clone();

    Ok(bitwarden_api_identity::models::AccountKeysRequestModel {
        public_key_encryption_key_pair,
        signature_key_pair,
        security_state,
        user_key_encrypted_account_private_key,
        account_public_key,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_api_identity::{
        apis::ApiClient as IdentityApiClient, models::RegisterFinishResponseModel,
    };
    use bitwarden_core::Client;

    use super::*;

    #[tokio::test]
    async fn test_post_user_password_registration_success() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let test_email = "test@example.com";
        let test_hint = "test hint";
        let test_password = "test-password-123";

        let identity_client = IdentityApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_register_finish()
                .once()
                .withf(|body| {
                    if let Some(req) = body {
                        // standard user entity information
                        assert_eq!(req.email, Some(test_email.to_string()));
                        assert_eq!(req.master_password_hint, Some(test_hint.to_string()));

                        // verifying new cryptographic data structures
                        assert!(req.account_keys.is_some());
                        let account_keys = req.account_keys.as_ref().unwrap();
                        assert!(
                            account_keys
                                .user_key_encrypted_account_private_key
                                .is_some()
                        );
                        assert!(account_keys.account_public_key.is_some());
                        assert!(account_keys.public_key_encryption_key_pair.is_some());
                        let public_key_encryption_key_pair = account_keys
                            .public_key_encryption_key_pair
                            .as_ref()
                            .unwrap();
                        assert!(public_key_encryption_key_pair.public_key.is_some());
                        assert!(public_key_encryption_key_pair.signed_public_key.is_some());
                        assert!(public_key_encryption_key_pair.wrapped_private_key.is_some());
                        assert!(account_keys.signature_key_pair.is_some());
                        let signature_key_pair = account_keys.signature_key_pair.as_ref().unwrap();
                        assert_eq!(
                            signature_key_pair.signature_algorithm,
                            Some("mldsa44".to_string())
                        );
                        assert!(signature_key_pair.verifying_key.is_some());
                        assert!(signature_key_pair.wrapped_signing_key.is_some());
                        assert!(account_keys.security_state.is_some());
                        let security_state = account_keys.security_state.as_ref().unwrap();
                        assert!(security_state.security_state.is_some());
                        assert_eq!(security_state.security_version, 2);
                        assert!(req.master_password_unlock.is_some());
                        let master_password_unlock = req.master_password_unlock.as_ref().unwrap();
                        assert_eq!(master_password_unlock.salt, test_email.to_string());
                        assert_eq!(
                            master_password_unlock.kdf,
                            Box::new(bitwarden_api_identity::models::KdfRequestModel {
                                kdf_type: bitwarden_api_identity::models::KdfType::Argon2id,
                                iterations: 6,
                                memory: Some(32),
                                parallelism: Some(4),
                            })
                        );
                        assert!(req.master_password_authentication.is_some());
                        let master_password_authentication =
                            req.master_password_authentication.as_ref().unwrap();
                        assert_eq!(master_password_authentication.salt, test_email.to_string());
                        assert_eq!(
                            master_password_authentication.kdf,
                            Box::new(bitwarden_api_identity::models::KdfRequestModel {
                                kdf_type: bitwarden_api_identity::models::KdfType::Argon2id,
                                iterations: 6,
                                memory: Some(32),
                                parallelism: Some(4),
                            })
                        );

                        // verify old cryptographic structures aren't set
                        assert!(req.user_asymmetric_keys.is_none());
                        assert!(req.kdf.is_none());
                        assert!(req.kdf_iterations.is_none());
                        assert!(req.kdf_memory.is_none());
                        assert!(req.kdf_parallelism.is_none());

                        // verify master password registration specific information
                        assert!(req.email_verification_token.is_none());
                        assert!(req.organization_user_id.is_none());
                        assert!(req.org_invite_token.is_none());
                        assert!(req.org_sponsored_free_family_plan_token.is_none());
                        assert!(req.accept_emergency_access_invite_token.is_none());
                        assert!(req.accept_emergency_access_id.is_none());
                        assert!(req.provider_invite_token.is_none());
                        assert!(req.provider_user_id.is_none());
                        true
                    } else {
                        false
                    }
                })
                .returning(move |_body| Ok(RegisterFinishResponseModel { object: None }));
        });

        let request = UserMasterPasswordRegistrationRequest {
            email: test_email.to_string(),
            salt: test_email.to_string(),
            master_password: test_password.to_string(),
            master_password_hint: Some(test_hint.to_string()),
            email_verification_token: None,
            organization_user_id: None,
            org_invite_token: None,
            org_sponsored_free_family_plan_token: None,
            accept_emergency_access_invite_token: None,
            accept_emergency_access_id: None,
            provider_invite_token: None,
            provider_user_id: None,
        };

        let result = internal_post_keys_for_user_password_registration(
            &registration_client,
            &identity_client,
            request,
        )
        .await;

        assert!(result.is_ok());

        // check that mock expectations were met
        if let IdentityApiClient::Mock(mut mock) = identity_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_user_password_registration_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let test_email = "test@example.com";
        let test_hint = "test hint";
        let test_password = "test-password-123";

        let identity_client = IdentityApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_register_finish()
                .once()
                .returning(move |_body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let request = UserMasterPasswordRegistrationRequest {
            email: test_email.to_string(),
            salt: test_email.to_string(),
            master_password: test_password.to_string(),
            master_password_hint: Some(test_hint.to_string()),
            email_verification_token: None,
            organization_user_id: None,
            org_invite_token: None,
            org_sponsored_free_family_plan_token: None,
            accept_emergency_access_invite_token: None,
            accept_emergency_access_id: None,
            provider_invite_token: None,
            provider_user_id: None,
        };

        let result = internal_post_keys_for_user_password_registration(
            &registration_client,
            &identity_client,
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // check that mock expectations were met
        if let IdentityApiClient::Mock(mut mock) = identity_client {
            mock.accounts_api.checkpoint();
        }
    }
}
