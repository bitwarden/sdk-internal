//! Initializes a new cryptographic state for a user and posts it to the server; enrolls in
//! admin password reset, unlocks the client and, if the user chose to, trusts this device.
use bitwarden_api_api::models::{
    KeysRequestModel, OrganizationUserResetPasswordEnrollmentRequestModel,
};
use bitwarden_core::{
    OrganizationId, UserId,
    key_management::{
        DeviceTrustError, TrustDeviceChoice,
        crypto::{InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::Kdf;
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
    /// The user's email address
    pub email: String,
    /// Whether to trust this device for TDE
    pub trust: TrustDeviceChoice,
}

#[bitwarden_ffi::wasm_export]
impl RegistrationClient {
    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls in
    /// admin password reset, persists the account cryptographic state, unlocks the client and, if
    /// the user chose to, trusts this device.
    pub async fn post_keys_for_tde_registration(
        &self,
        request: TdeRegistrationRequest,
    ) -> Result<(), RegistrationError> {
        let client = &self.client;
        let bridge = client.km_state_bridge();
        if !bridge.is_bridge_registered() {
            return Err(RegistrationError::StateBridgeNotRegistered);
        }

        // First call crypto API to get all keys
        info!("Initializing account cryptography");
        let tde_registration_crypto_result = client
            .crypto()
            .make_user_tde_registration(request.org_public_key.clone())
            .map_err(|_| RegistrationError::Crypto)?;

        // Post the generated keys to the API here. The user now has keys and is "registered", but
        // has no unlock method.
        let keys_request = KeysRequestModel {
            account_keys: Some(Box::new(
                tde_registration_crypto_result.account_keys_request.clone(),
            )),
            // Note: This property is deprecated and will be removed
            public_key: tde_registration_crypto_result
                .account_keys_request
                .account_public_key
                .ok_or(RegistrationError::Crypto)?,
            // Note: This property is deprecated and will be removed
            encrypted_private_key: tde_registration_crypto_result
                .account_keys_request
                .user_key_encrypted_account_private_key
                .ok_or(RegistrationError::Crypto)?,
            user_key_id: tde_registration_crypto_result
                .user_key
                .key_id()
                .map(|id| id.to_string()),
        };
        let api_client = &client.internal.get_api_configurations().api_client;
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

        // Persist the account state before unlocking: hosts initialize their user client from it.
        bridge
            .set_account_cryptographic_state(
                &tde_registration_crypto_result.account_cryptographic_state,
            )
            .await;

        info!("Unlocking the new account");
        client
            .crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: Some(request.user_id),
                // A TDE user has no master password, so the KDF is never used to derive a key.
                kdf_params: Kdf::default_pbkdf2(),
                email: request.email,
                account_cryptographic_state: tde_registration_crypto_result
                    .account_cryptographic_state,
                method: InitUserCryptoMethod::DecryptedKey {
                    decrypted_user_key: tde_registration_crypto_result
                        .user_key
                        .to_base64()
                        .to_string(),
                },
                upgrade_token: None,
            })
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlock the new account: {e:?}");
                RegistrationError::Crypto
            })?;

        if request.trust == TrustDeviceChoice::Trust {
            info!("Enrolling into trusted device decryption");
            client
                .device_trust()
                .trust_device()
                .await
                .map_err(|e| match e {
                    DeviceTrustError::Api => RegistrationError::Api,
                    DeviceTrustError::StateBridgeNotRegistered => {
                        RegistrationError::StateBridgeNotRegistered
                    }
                    DeviceTrustError::MissingDeviceIdentifier => {
                        RegistrationError::InvalidInput("no device identifier".to_owned())
                    }
                    DeviceTrustError::Locked | DeviceTrustError::Crypto => {
                        RegistrationError::Crypto
                    }
                })?;
        }

        info!("User initialized!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{DeviceResponseModel, KeysResponseModel},
    };
    use bitwarden_core::{
        Client, ClientSettings, client::internal::ApiConfigurations,
        key_management::state_bridge::test_support::InMemoryStateBridge,
    };

    use super::*;

    const TEST_USER_ID: &str = "060000fb-0922-4dd3-b170-6e15cb5df8c8";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_DEVICE_ID: &str = "test-device-id";
    const TEST_EMAIL: &str = "tde@example.com";

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

    /// Which server calls a scenario expects, in order of the registration flow.
    struct Expected {
        post_keys: Result<(), ()>,
        enrollment: Option<Result<(), ()>>,
        device_keys: Option<Result<(), ()>>,
    }

    fn api_error() -> bitwarden_api_api::apis::Error {
        serde_json::Error::io(std::io::Error::other("API error")).into()
    }

    fn device_response() -> DeviceResponseModel {
        DeviceResponseModel {
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
        }
    }

    fn mocked_api(expected: Expected) -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            let post_keys = expected.post_keys;
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_| {
                    post_keys
                        .map(|()| KeysResponseModel {
                            object: None,
                            key: None,
                            public_key: None,
                            private_key: None,
                            account_keys: None,
                        })
                        .map_err(|()| api_error())
                });

            match expected.enrollment {
                Some(result) => {
                    mock.organization_users_api
                        .expect_put_reset_password_enrollment()
                        .once()
                        .returning(move |_, _, _| result.map_err(|()| api_error()));
                }
                None => {
                    mock.organization_users_api
                        .expect_put_reset_password_enrollment()
                        .never();
                }
            }

            match expected.device_keys {
                Some(result) => {
                    mock.devices_api
                        .expect_put_keys()
                        .once()
                        .returning(move |identifier, _| {
                            assert_eq!(identifier, TEST_DEVICE_ID);
                            result.map(|()| device_response()).map_err(|()| api_error())
                        });
                }
                None => {
                    mock.devices_api.expect_put_keys().never();
                }
            }
        })
    }

    fn registration_client(api: ApiClient) -> (Client, RegistrationClient) {
        let client = Client::builder()
            .with_settings(ClientSettings {
                device_identifier: Some(TEST_DEVICE_ID.to_owned()),
                ..Default::default()
            })
            .with_api_configurations(Arc::new(ApiConfigurations::from_api_client(api)))
            .build();
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        (client.clone(), RegistrationClient::new(client))
    }

    fn request(trust: TrustDeviceChoice) -> TdeRegistrationRequest {
        TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            email: TEST_EMAIL.to_owned(),
            trust,
        }
    }

    #[tokio::test]
    async fn registration_unlocks_and_trusts_the_device() {
        let (client, registration) = registration_client(mocked_api(Expected {
            post_keys: Ok(()),
            enrollment: Some(Ok(())),
            device_keys: Some(Ok(())),
        }));

        registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::Trust))
            .await
            .unwrap();

        assert!(client.crypto().get_user_encryption_key().await.is_ok());
        let bridge = client.km_state_bridge();
        assert!(bridge.get_account_cryptographic_state().await.is_some());
        assert!(bridge.get_device_key().await.is_some());
    }

    #[tokio::test]
    async fn registration_skips_device_trust_when_declined() {
        let (client, registration) = registration_client(mocked_api(Expected {
            post_keys: Ok(()),
            enrollment: Some(Ok(())),
            device_keys: None,
        }));

        registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::DontTrust))
            .await
            .unwrap();

        assert!(client.crypto().get_user_encryption_key().await.is_ok());
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn registration_fails_when_posting_keys_fails() {
        let (client, registration) = registration_client(mocked_api(Expected {
            post_keys: Err(()),
            enrollment: None,
            device_keys: None,
        }));

        let result = registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::Trust))
            .await;

        assert!(matches!(result, Err(RegistrationError::Api)));
        assert!(client.crypto().get_user_encryption_key().await.is_err());
    }

    #[tokio::test]
    async fn registration_fails_when_enrollment_fails() {
        let (client, registration) = registration_client(mocked_api(Expected {
            post_keys: Ok(()),
            enrollment: Some(Err(())),
            device_keys: None,
        }));

        let result = registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::Trust))
            .await;

        assert!(matches!(result, Err(RegistrationError::Api)));
        assert!(
            client
                .km_state_bridge()
                .get_account_cryptographic_state()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn registration_fails_when_device_keys_fail_but_stays_unlocked() {
        let (client, registration) = registration_client(mocked_api(Expected {
            post_keys: Ok(()),
            enrollment: Some(Ok(())),
            device_keys: Some(Err(())),
        }));

        let result = registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::Trust))
            .await;

        assert!(matches!(result, Err(RegistrationError::Api)));
        assert!(client.crypto().get_user_encryption_key().await.is_ok());
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn registration_requires_a_state_bridge() {
        let client = Client::new(None);
        let registration = RegistrationClient::new(client);

        let result = registration
            .post_keys_for_tde_registration(request(TrustDeviceChoice::Trust))
            .await;

        assert!(matches!(
            result,
            Err(RegistrationError::StateBridgeNotRegistered)
        ));
    }
}
