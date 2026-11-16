//! Initializes a new cryptographic state for a user and posts it to the server; enrolls in
//! admin password reset and finally enrolls the user to TDE unlock.
use bitwarden_api_api::models::{
    DeviceKeysRequestModel, KeysRequestModel, OrganizationUserResetPasswordEnrollmentRequestModel,
    SsoJitProvisionFinishTrustedDeviceRequestModel,
};
use bitwarden_core::{
    OrganizationId, UserId,
    key_management::{
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::MakeTdeRegistrationResponse,
    },
};
use bitwarden_encoding::B64;
use tracing::info;

use crate::registration::{RegistrationClient, RegistrationError};

/// Request parameters for TDE (Trusted Device Encryption) registration.
#[bitwarden_ffi::wasm_record]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TdeRegistrationRequest {
    /// Organization ID to enroll in
    pub org_id: OrganizationId,
    /// Organization's public key for encrypting the reset password key. This should be verified by
    /// the client and not verifying may compromise the security of the user's account.
    pub org_public_key: B64,
    /// User ID for the account being initialized
    pub user_id: UserId,
    /// Device identifier for TDE enrollment
    pub device_identifier: String,
    /// Whether to trust this device for TDE
    pub trust_device: bool,
    /// Whether the server moves the pending organization membership from Invited to Accepted and
    /// enrolls the user in admin account recovery. Send `false` for open-invite links so the
    /// membership stays Invited for later Admin Console checks. Defaults to `true` when not set.
    /// Only used when the `pm-34429-invite-link-auto-confirm` flag is on.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub accept_organization_invite: Option<bool>,
}

/// Result of TDE registration process.
#[bitwarden_ffi::wasm_record]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TdeRegistrationResponse {
    /// The account cryptographic state of the user
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The device key
    pub device_key: B64,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: B64,
}

#[bitwarden_ffi::wasm_export]
impl RegistrationClient {
    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls in
    /// admin password reset and finally enrolls the user to TDE unlock.
    pub async fn post_keys_for_tde_registration(
        &self,
        request: TdeRegistrationRequest,
    ) -> Result<TdeRegistrationResponse, RegistrationError> {
        let client = &self.client.internal;
        let api_client = &client.get_api_configurations().api_client;
        internal_post_keys_for_tde_registration(self, api_client, request).await
    }
}

async fn internal_post_keys_for_tde_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: TdeRegistrationRequest,
) -> Result<TdeRegistrationResponse, RegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let tde_registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_tde_registration(request.org_public_key.clone())
        .map_err(|_| RegistrationError::Crypto)?;

    // TODO: Remove the legacy flow when the pm-34429-invite-link-auto-confirm flag is removed
    // with https://bitwarden.atlassian.net/browse/PM-40052
    if registration_client
        .client
        .flags()
        .get()
        .await
        .invite_link_auto_confirm
    {
        sso_jit_provision_finish_trusted_device(
            api_client,
            &request,
            &tde_registration_crypto_result,
        )
        .await?;
    } else {
        legacy_post_keys_for_tde_registration(
            api_client,
            &request,
            &tde_registration_crypto_result,
        )
        .await?;
    }

    info!("User initialized!");
    // Note: This passing out of state and keys is temporary. Once SDK state management is more
    // mature, the account cryptographic state and keys should be set directly here.
    Ok(TdeRegistrationResponse {
        account_cryptographic_state: tde_registration_crypto_result.account_cryptographic_state,
        device_key: tde_registration_crypto_result
            .trusted_device_keys
            .device_key,
        user_key: tde_registration_crypto_result
            .user_key
            .to_encoded()
            .to_vec()
            .into(),
    })
}

/// Posts the keys and trusts the device in one request. The server reads the device from
/// the access token, so `request.device_identifier` is not sent.
async fn sso_jit_provision_finish_trusted_device(
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: &TdeRegistrationRequest,
    tde_registration_crypto_result: &MakeTdeRegistrationResponse,
) -> Result<(), RegistrationError> {
    let accept_organization_invite = request.accept_organization_invite.unwrap_or(true);
    let api_request = SsoJitProvisionFinishTrustedDeviceRequestModel {
        device_keys: request
            .trust_device
            .then(|| Box::new(make_device_keys_request(tde_registration_crypto_result))),
        // The server enrolls in admin account recovery only when it accepts the invite, and then
        // it requires the account recovery key.
        account_recovery_key: accept_organization_invite.then(|| {
            tde_registration_crypto_result
                .reset_password_key
                .to_string()
        }),
        ..SsoJitProvisionFinishTrustedDeviceRequestModel::new(
            make_keys_request(tde_registration_crypto_result)?,
            request.org_id.into(),
            accept_organization_invite,
        )
    };
    info!("Posting user account cryptographic state to server");
    api_client
        .sso_jit_provision_finish_api()
        .finish_trusted_device(Some(api_request))
        .await
        .map_err(|e| {
            tracing::error!("Failed to finish SSO JIT provisioning: {e:?}");
            RegistrationError::Api
        })
}

async fn legacy_post_keys_for_tde_registration(
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: &TdeRegistrationRequest,
    tde_registration_crypto_result: &MakeTdeRegistrationResponse,
) -> Result<(), RegistrationError> {
    // Post the generated keys to the API here. The user now has keys and is "registered", but
    // has no unlock method.
    let keys_request = make_keys_request(tde_registration_crypto_result)?;
    info!("Posting user account cryptographic state to server");
    api_client
        .accounts_api()
        .post_keys(Some(keys_request))
        .await
        .map_err(|e| {
            tracing::error!("Failed to post account keys: {e:?}");
            RegistrationError::Api
        })?;

    // Next, enroll the user for reset password using the reset password key generated above.
    info!("Enrolling into admin account recovery");
    api_client
        .organization_users_api()
        .put_reset_password_enrollment(
            request.org_id.into(),
            request.user_id.into(),
            Some(OrganizationUserResetPasswordEnrollmentRequestModel {
                reset_password_key: Some(
                    tde_registration_crypto_result
                        .reset_password_key
                        .to_string(),
                ),
                master_password_hash: None,
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to enroll for reset password: {e:?}");
            RegistrationError::Api
        })?;

    if request.trust_device {
        // Next, enroll the user for TDE unlock
        info!("Enrolling into trusted device decryption");
        api_client
            .devices_api()
            .put_keys(
                request.device_identifier.as_str(),
                Some(make_device_keys_request(tde_registration_crypto_result)),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to enroll device for TDE: {e:?}");
                RegistrationError::Api
            })?;
    }

    Ok(())
}

fn make_keys_request(
    tde_registration_crypto_result: &MakeTdeRegistrationResponse,
) -> Result<KeysRequestModel, RegistrationError> {
    Ok(KeysRequestModel {
        account_keys: Some(Box::new(
            tde_registration_crypto_result.account_keys_request.clone(),
        )),
        // Note: This property is deprecated and will be removed
        public_key: tde_registration_crypto_result
            .account_keys_request
            .account_public_key
            .clone()
            .ok_or(RegistrationError::Crypto)?,
        // Note: This property is deprecated and will be removed
        encrypted_private_key: tde_registration_crypto_result
            .account_keys_request
            .user_key_encrypted_account_private_key
            .clone()
            .ok_or(RegistrationError::Crypto)?,
        user_key_id: tde_registration_crypto_result
            .user_key
            .key_id()
            .map(|id| id.to_string()),
    })
}

fn make_device_keys_request(
    tde_registration_crypto_result: &MakeTdeRegistrationResponse,
) -> DeviceKeysRequestModel {
    let trusted_device_keys = &tde_registration_crypto_result.trusted_device_keys;
    DeviceKeysRequestModel {
        encrypted_user_key: trusted_device_keys.protected_user_key.to_string(),
        encrypted_public_key: trusted_device_keys.protected_device_public_key.to_string(),
        encrypted_private_key: trusted_device_keys.protected_device_private_key.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{DeviceResponseModel, KeysResponseModel},
    };
    use bitwarden_core::Client;
    use bitwarden_crypto::{EncString, UnsignedSharedKey};

    use super::*;

    const TEST_USER_ID: &str = "060000fb-0922-4dd3-b170-6e15cb5df8c8";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_DEVICE_ID: &str = "test-device-id";

    const TEST_ORG_PUBLIC_KEY: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 173, 4, 54, 63, 125, 12, 254, 38, 115, 34, 95, 164, 148,
        115, 86, 140, 129, 74, 19, 70, 212, 212, 130, 163, 105, 249, 101, 120, 154, 46, 194, 250,
        229, 242, 156, 67, 109, 179, 187, 134, 59, 235, 60, 107, 144, 163, 35, 22, 109, 230, 134,
        243, 44, 243, 79, 84, 76, 11, 64, 56, 236, 167, 98, 26, 30, 213, 143, 105, 52, 92, 129, 92,
        88, 22, 115, 135, 63, 215, 79, 8, 11, 183, 124, 10, 73, 231, 170, 110, 210, 178, 22, 100,
        76, 75, 118, 202, 252, 204, 67, 204, 152, 6, 244, 208, 161, 146, 103, 225, 233, 239, 88,
        195, 88, 150, 230, 111, 62, 142, 12, 157, 184, 155, 34, 84, 237, 111, 11, 97, 56, 152, 130,
        14, 72, 123, 140, 47, 137, 5, 97, 166, 4, 147, 111, 23, 65, 78, 63, 208, 198, 50, 161, 39,
        80, 143, 100, 194, 37, 252, 194, 53, 207, 166, 168, 250, 165, 121, 9, 207, 90, 36, 213,
        211, 84, 255, 14, 205, 114, 135, 217, 137, 105, 232, 58, 169, 222, 10, 13, 138, 203, 16,
        12, 122, 72, 227, 95, 160, 111, 54, 200, 198, 143, 156, 15, 143, 196, 50, 150, 204, 144,
        255, 162, 248, 50, 28, 47, 66, 9, 83, 158, 67, 9, 50, 147, 174, 147, 200, 199, 238, 190,
        248, 60, 114, 218, 32, 209, 120, 218, 17, 234, 14, 128, 192, 166, 33, 60, 73, 227, 108,
        201, 41, 160, 81, 133, 171, 205, 221, 2, 3, 1, 0, 1,
    ];

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_success() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .withf(|body| {
                    let body = body.as_ref().unwrap();
                    let account_keys = body.account_keys.as_ref().unwrap();
                    assert_eq!(
                        Some(&body.public_key),
                        account_keys.account_public_key.as_ref()
                    );
                    assert_eq!(
                        Some(&body.encrypted_private_key),
                        account_keys.user_key_encrypted_account_private_key.as_ref()
                    );
                    assert!(EncString::from_str(&body.encrypted_private_key).is_ok());
                    assert!(body.user_key_id.is_some());
                    true
                })
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .withf(|org_id, user_id, body| {
                    assert_eq!(*org_id, uuid::uuid!(TEST_ORG_ID));
                    assert_eq!(*user_id, uuid::uuid!(TEST_USER_ID));
                    let body = body.as_ref().unwrap();
                    assert!(
                        UnsignedSharedKey::from_str(body.reset_password_key.as_ref().unwrap())
                            .is_ok()
                    );
                    assert!(body.master_password_hash.is_none());
                    true
                })
                .returning(move |_org_id, _user_id, _body| Ok(()));
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_device_id, body| {
                    let body = body.unwrap();
                    assert!(UnsignedSharedKey::from_str(body.encrypted_user_key.as_str()).is_ok());
                    assert!(matches!(
                        EncString::from_str(body.encrypted_private_key.as_str()).unwrap(),
                        EncString::Aes256Cbc_HmacSha256_B64 { .. }
                    ));
                    assert!(matches!(
                        EncString::from_str(body.encrypted_public_key.as_str()).unwrap(),
                        EncString::Cose_Encrypt0_B64 { .. }
                    ));

                    Ok(DeviceResponseModel {
                        object: None,
                        id: None,
                        name: None,
                        r#type: None,
                        identifier: None,
                        creation_date: None,
                        last_activity_date: None,
                        is_trusted: None,
                        encrypted_user_key: None,
                        encrypted_public_key: None,
                    })
                });
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
            accept_organization_invite: Some(false),
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_ok());
        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_trust_device_false() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| Ok(()));
            // Explicitly expect that put_keys is never called when trust_device is false
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: false, // trust_device is false
            accept_organization_invite: None,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_ok());
        // Assert that the mock expectations were met (put_keys should not have been called)
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_post_keys_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
            // Subsequent API calls should not be made if post_keys fails
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .never();
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
            accept_organization_invite: None,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_reset_password_enrollment_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
            // Device key enrollment should not be made if reset password enrollment fails
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
            accept_organization_invite: None,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_device_keys_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| Ok(()));
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_device_id, _body| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true, // trust_device is true, so device enrollment should be attempted
            accept_organization_invite: None,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    async fn client_with_invite_link_auto_confirm() -> Client {
        let client = Client::new(None);
        client
            .flags()
            .load(HashMap::from([(
                "pm-34429-invite-link-auto-confirm".to_string(),
                true,
            )]))
            .await;
        client
    }

    fn sso_jit_tde_request(
        trust_device: bool,
        accept_organization_invite: Option<bool>,
    ) -> TdeRegistrationRequest {
        TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device,
            accept_organization_invite,
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_invite_link_auto_confirm_success() {
        // `None` defaults to accepting the invite.
        for (trust_device, accept_organization_invite, expected_accept) in [
            (true, None, true),
            (false, None, true),
            (true, Some(true), true),
            (true, Some(false), false),
            (false, Some(false), false),
        ] {
            let client = client_with_invite_link_auto_confirm().await;
            let registration_client = RegistrationClient::new(client);

            let api_client = ApiClient::new_mocked(|mock| {
                mock.sso_jit_provision_finish_api
                    .expect_finish_trusted_device()
                    .once()
                    .withf(move |body| {
                        let req = body.as_ref().unwrap();
                        assert_eq!(req.organization_id, uuid::uuid!(TEST_ORG_ID));
                        assert_eq!(req.accept_organization_invite, expected_accept);
                        let account_keys = req.keys.account_keys.as_ref().unwrap();
                        assert_eq!(
                            Some(&req.keys.public_key),
                            account_keys.account_public_key.as_ref()
                        );
                        assert_eq!(
                            Some(&req.keys.encrypted_private_key),
                            account_keys.user_key_encrypted_account_private_key.as_ref()
                        );
                        assert!(EncString::from_str(&req.keys.encrypted_private_key).is_ok());
                        assert!(req.keys.user_key_id.is_some());
                        if let Some(account_recovery_key) = &req.account_recovery_key {
                            assert!(UnsignedSharedKey::from_str(account_recovery_key).is_ok());
                        }
                        assert_eq!(req.account_recovery_key.is_some(), expected_accept);
                        assert_eq!(req.device_keys.is_some(), trust_device);
                        if let Some(device_keys) = &req.device_keys {
                            assert!(
                                UnsignedSharedKey::from_str(
                                    device_keys.encrypted_user_key.as_str()
                                )
                                .is_ok()
                            );
                            assert!(matches!(
                                EncString::from_str(device_keys.encrypted_private_key.as_str())
                                    .unwrap(),
                                EncString::Aes256Cbc_HmacSha256_B64 { .. }
                            ));
                            assert!(matches!(
                                EncString::from_str(device_keys.encrypted_public_key.as_str())
                                    .unwrap(),
                                EncString::Cose_Encrypt0_B64 { .. }
                            ));
                        }
                        true
                    })
                    .returning(move |_body| Ok(()));
                // The new endpoint replaces these three calls
                mock.accounts_api.expect_post_keys().never();
                mock.organization_users_api
                    .expect_put_reset_password_enrollment()
                    .never();
                mock.devices_api.expect_put_keys().never();
            });

            let result = internal_post_keys_for_tde_registration(
                &registration_client,
                &api_client,
                sso_jit_tde_request(trust_device, accept_organization_invite),
            )
            .await;

            assert!(result.is_ok());
            // Assert that the mock expectations were met
            if let ApiClient::Mock(mut mock) = api_client {
                mock.sso_jit_provision_finish_api.checkpoint();
                mock.accounts_api.checkpoint();
                mock.organization_users_api.checkpoint();
                mock.devices_api.checkpoint();
            }
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_invite_link_auto_confirm_api_failure() {
        let client = client_with_invite_link_auto_confirm().await;
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.sso_jit_provision_finish_api
                .expect_finish_trusted_device()
                .once()
                .returning(move |_body| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
        });

        let result = internal_post_keys_for_tde_registration(
            &registration_client,
            &api_client,
            sso_jit_tde_request(true, None),
        )
        .await;

        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sso_jit_provision_finish_api.checkpoint();
        }
    }
}
