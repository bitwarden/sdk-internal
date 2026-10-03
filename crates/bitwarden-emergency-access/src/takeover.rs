use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    EmergencyAccessPasswordRequestModel, EmergencyAccessTakeoverResponseModel, KdfType,
};
use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{
        MasterPasswordAuthenticationData, MasterPasswordError, MasterPasswordUnlockData,
        PrivateKeySlotId,
    },
    require,
};
use bitwarden_crypto::{CryptoError, Kdf, UnsignedSharedKey};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when taking over a grantor's account through emergency access.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessTakeoverError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The grantor key is malformed or could not be decapsulated with the current user's private
    /// key.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The grantor's KDF is malformed, or the new master password data could not be derived.
    #[error(transparent)]
    MasterPassword(#[from] MasterPasswordError),
}

/// The takeover response parsed: the grantor key, KDF and salt.
struct EmergencyAccessTakeoverData {
    grantor_key: UnsignedSharedKey,
    kdf: Kdf,
    /// `None` on servers that predate the salt field.
    salt: Option<String>,
}

impl TryFrom<EmergencyAccessTakeoverResponseModel> for EmergencyAccessTakeoverData {
    type Error = EmergencyAccessTakeoverError;

    fn try_from(response: EmergencyAccessTakeoverResponseModel) -> Result<Self, Self::Error> {
        let grantor_key = require!(response.key_encrypted).parse()?;

        let iterations = require!(response.kdf_iterations);
        let kdf = match require!(response.kdf) {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: kdf_parse_nonzero_u32(iterations)?,
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: kdf_parse_nonzero_u32(iterations)?,
                memory: kdf_parse_nonzero_u32(require!(response.kdf_memory))?,
                parallelism: kdf_parse_nonzero_u32(require!(response.kdf_parallelism))?,
            },
            KdfType::__Unknown(_) => return Err(MasterPasswordError::KdfMalformed.into()),
        };

        Ok(Self {
            grantor_key,
            kdf,
            salt: response.salt,
        })
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Sets a new master password on the grantor's account of an approved takeover emergency
    /// access.
    ///
    /// `grantor_email` is used as salt when the server doesn't return one.
    ///
    /// Called by the grantee.
    pub async fn takeover(
        &self,
        emergency_access_id: EmergencyAccessId,
        new_password: String,
        grantor_email: String,
    ) -> Result<(), EmergencyAccessTakeoverError> {
        // The server returns the grantor's user key encapsulated to the current user's public key,
        // and the grantor's KDF. The new master password is derived with that KDF and wraps the
        // grantor's user key, which only lives in the key store while doing so.
        let api = self.api_configurations.api_client.emergency_access_api();

        let response = api.takeover(emergency_access_id.into()).await?;
        let data = EmergencyAccessTakeoverData::try_from(response)?;

        // Servers that predate the salt field use the email-derived salt.
        // TODO: PM-32059 - drop the fallback once the salt is decoupled from the email.
        let salt = data
            .salt
            .unwrap_or_else(|| grantor_email.trim().to_lowercase());

        // The key store context must not be held across the await below, so it is scoped here.
        // TODO: Move this crypto into a dedicated bitwarden-emergency-access-crypto crate.
        let request = {
            let mut ctx = self.key_store.context();
            let grantor_key = data
                .grantor_key
                .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)?;

            let authentication_data =
                MasterPasswordAuthenticationData::derive(&new_password, &data.kdf, &salt)?;
            let unlock_data = MasterPasswordUnlockData::derive(
                &new_password,
                &data.kdf,
                &salt,
                grantor_key,
                &ctx,
            )?;

            EmergencyAccessPasswordRequestModel {
                new_master_password_hash: None,
                key: None,
                unlock_data: Some(Box::new((&unlock_data).into())),
                authentication_data: Some(Box::new((&authentication_data).into())),
            }
        };

        api.password(emergency_access_id.into(), Some(request))
            .await?;

        Ok(())
    }
}

fn kdf_parse_nonzero_u32(value: i32) -> Result<NonZeroU32, MasterPasswordError> {
    u32::try_from(value)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(MasterPasswordError::KdfMalformed)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_api_api::models::KdfRequestModel;
    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account_v2};
    use bitwarden_crypto::EncString;

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{
            TEST_VECTOR_GRANTOR_KEY, TEST_VECTOR_WRONG_GRANTOR_KEY, api_error, is_test_id,
            test_client, test_id,
        },
    };

    const TEST_NEW_PASSWORD: &str = "new master password";
    const TEST_GRANTOR_EMAIL: &str = " Test@Bitwarden.com ";
    const TEST_SALT: &str = "server-salt";
    const TEST_ITERATIONS: i32 = 600_000;

    fn response(
        key_encrypted: Option<&str>,
        salt: Option<&str>,
    ) -> EmergencyAccessTakeoverResponseModel {
        EmergencyAccessTakeoverResponseModel {
            object: None,
            kdf: Some(KdfType::PBKDF2_SHA256),
            kdf_iterations: Some(TEST_ITERATIONS),
            kdf_memory: None,
            kdf_parallelism: None,
            key_encrypted: key_encrypted.map(str::to_owned),
            salt: salt.map(str::to_owned),
        }
    }

    fn pbkdf2() -> Kdf {
        Kdf::PBKDF2 {
            iterations: NonZeroU32::new(TEST_ITERATIONS as u32).unwrap(),
        }
    }

    /// Takes over as the grantee and returns the result and the password request sent, if any.
    async fn takeover(
        response: EmergencyAccessTakeoverResponseModel,
    ) -> (
        Client,
        Result<(), EmergencyAccessTakeoverError>,
        Option<EmergencyAccessPasswordRequestModel>,
    ) {
        let sent = Arc::new(Mutex::new(None));
        let captured = sent.clone();

        let client = test_client(test_bitwarden_com_account_v2(), move |mock| {
            mock.emergency_access_api
                .expect_takeover()
                .withf(is_test_id)
                .returning(move |_| Ok(response.clone()))
                .once();
            mock.emergency_access_api
                .expect_password()
                .withf(|id, _| is_test_id(id))
                .returning(move |_, request| {
                    *captured.lock().unwrap() = request;
                    Ok(())
                });
        })
        .await;

        let result = client
            .emergency_access()
            .takeover(
                test_id(),
                TEST_NEW_PASSWORD.to_owned(),
                TEST_GRANTOR_EMAIL.to_owned(),
            )
            .await;

        let request = sent.lock().unwrap().take();
        (client, result, request)
    }

    /// Asserts the request sets the new password with `salt` and wraps the grantor's user key.
    fn assert_sets_new_password(
        client: &Client,
        request: EmergencyAccessPasswordRequestModel,
        salt: &str,
    ) {
        let expected_kdf = KdfRequestModel {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: TEST_ITERATIONS,
            memory: None,
            parallelism: None,
        };

        // Only the new authentication and unlock data are sent, like the clients did.
        assert_eq!(request.new_master_password_hash, None);
        assert_eq!(request.key, None);

        let authentication = request.authentication_data.unwrap();
        assert_eq!(*authentication.kdf, expected_kdf);
        assert_eq!(authentication.salt, salt);
        assert_eq!(
            authentication.master_password_authentication_hash,
            MasterPasswordAuthenticationData::derive(TEST_NEW_PASSWORD, &pbkdf2(), salt)
                .unwrap()
                .master_password_authentication_hash
                .to_string()
        );

        let unlock = request.unlock_data.unwrap();
        assert_eq!(*unlock.kdf, expected_kdf);
        assert_eq!(unlock.salt, salt);

        // The new password unwraps the same key as the recorded grantor key vector: the
        // grantor's user key.
        let unlock_data = MasterPasswordUnlockData {
            kdf: pbkdf2(),
            master_key_wrapped_user_key: unlock
                .master_key_wrapped_user_key
                .parse::<EncString>()
                .unwrap(),
            salt: unlock.salt,
            contained_key_id: None,
        };
        let recorded_key: UnsignedSharedKey = TEST_VECTOR_GRANTOR_KEY.parse().unwrap();

        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        let unwrapped = unlock_data
            .unwrap_to_context(TEST_NEW_PASSWORD, &mut ctx)
            .unwrap();
        let recorded = recorded_key
            .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)
            .unwrap();

        #[allow(deprecated)]
        let (unwrapped, recorded) = (
            ctx.dangerous_get_symmetric_key(unwrapped).unwrap(),
            ctx.dangerous_get_symmetric_key(recorded).unwrap(),
        );
        assert_eq!(unwrapped, recorded);
    }

    #[tokio::test]
    async fn sets_new_password_with_server_salt() {
        let (client, result, request) =
            takeover(response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))).await;

        result.unwrap();
        assert_sets_new_password(&client, request.unwrap(), TEST_SALT);
    }

    #[tokio::test]
    async fn falls_back_to_email_salt() {
        let (client, result, request) =
            takeover(response(Some(TEST_VECTOR_GRANTOR_KEY), None)).await;

        result.unwrap();
        assert_sets_new_password(&client, request.unwrap(), "test@bitwarden.com");
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_not_for_current_user() {
        let (_, result, request) = takeover(response(
            Some(TEST_VECTOR_WRONG_GRANTOR_KEY),
            Some(TEST_SALT),
        ))
        .await;

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::Crypto(_))
        ));
        assert!(request.is_none());
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_malformed() {
        let (_, result, request) = takeover(response(Some("not a key"), Some(TEST_SALT))).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::Crypto(_))
        ));
        assert!(request.is_none());
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_missing() {
        let (_, result, request) = takeover(response(None, Some(TEST_SALT))).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::MissingField(_))
        ));
        assert!(request.is_none());
    }

    #[tokio::test]
    async fn fails_when_kdf_is_missing() {
        let response = EmergencyAccessTakeoverResponseModel {
            kdf: None,
            ..response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))
        };

        let (_, result, request) = takeover(response).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::MissingField(_))
        ));
        assert!(request.is_none());
    }

    #[tokio::test]
    async fn fails_when_kdf_is_malformed() {
        let response = EmergencyAccessTakeoverResponseModel {
            kdf_iterations: Some(0),
            ..response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))
        };

        let (_, result, request) = takeover(response).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::MasterPassword(
                MasterPasswordError::KdfMalformed
            ))
        ));
        assert!(request.is_none());
    }

    #[tokio::test]
    async fn fails_when_takeover_request_fails() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_takeover()
                .returning(|_| api_error())
                .once();
            mock.emergency_access_api.expect_password().never();
        })
        .await;

        let result = client
            .emergency_access()
            .takeover(
                test_id(),
                TEST_NEW_PASSWORD.to_owned(),
                TEST_GRANTOR_EMAIL.to_owned(),
            )
            .await;

        assert!(matches!(result, Err(EmergencyAccessTakeoverError::Api(_))));
    }

    #[tokio::test]
    async fn fails_when_password_request_fails() {
        let response = response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT));
        let client = test_client(test_bitwarden_com_account_v2(), move |mock| {
            mock.emergency_access_api
                .expect_takeover()
                .returning(move |_| Ok(response.clone()))
                .once();
            mock.emergency_access_api
                .expect_password()
                .returning(|_, _| api_error())
                .once();
        })
        .await;

        let result = client
            .emergency_access()
            .takeover(
                test_id(),
                TEST_NEW_PASSWORD.to_owned(),
                TEST_GRANTOR_EMAIL.to_owned(),
            )
            .await;

        assert!(matches!(result, Err(EmergencyAccessTakeoverError::Api(_))));
    }

    #[test]
    fn parses_argon2id_kdf() {
        let response = EmergencyAccessTakeoverResponseModel {
            kdf: Some(KdfType::Argon2id),
            kdf_iterations: Some(3),
            kdf_memory: Some(64),
            kdf_parallelism: Some(4),
            ..response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))
        };

        let data = EmergencyAccessTakeoverData::try_from(response).unwrap();

        assert_eq!(
            data.kdf,
            Kdf::Argon2id {
                iterations: NonZeroU32::new(3).unwrap(),
                memory: NonZeroU32::new(64).unwrap(),
                parallelism: NonZeroU32::new(4).unwrap(),
            }
        );
    }

    #[test]
    fn rejects_argon2id_kdf_without_memory() {
        let response = EmergencyAccessTakeoverResponseModel {
            kdf: Some(KdfType::Argon2id),
            kdf_parallelism: Some(4),
            ..response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))
        };

        let result = EmergencyAccessTakeoverData::try_from(response);

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::MissingField(_))
        ));
    }

    #[test]
    fn rejects_unknown_kdf() {
        let response = EmergencyAccessTakeoverResponseModel {
            kdf: Some(KdfType::__Unknown(9)),
            ..response(Some(TEST_VECTOR_GRANTOR_KEY), Some(TEST_SALT))
        };

        let result = EmergencyAccessTakeoverData::try_from(response);

        assert!(matches!(
            result,
            Err(EmergencyAccessTakeoverError::MasterPassword(
                MasterPasswordError::KdfMalformed
            ))
        ));
    }
}
