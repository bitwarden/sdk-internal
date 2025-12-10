use bitwarden_api_identity::models::{
    KdfSettings, KdfType, PasswordPreloginRequestModel, PasswordPreloginResponseModel,
};
use bitwarden_core::{ApiError, MissingFieldError, require};
use bitwarden_crypto::Kdf;
use bitwarden_error::bitwarden_error;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::IdentityClient;

/// Error type for password prelogin operations
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PasswordPreloginError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Response containing the data required before password-based authentication
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))] // add mobile support
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)] // add wasm support
pub struct PasswordPreloginData {
    /// The Key Derivation Function (KDF) configuration for the user
    pub kdf: Kdf,

    /// The salt used in the KDF process
    pub salt: String,
}

impl IdentityClient {
    /// Retrieves the data required before authenticating with a password.
    /// This includes the user's KDF configuration needed to properly derive the master key.
    ///
    /// # Arguments
    /// * `email` - The user's email address
    ///
    /// # Returns
    /// * `PreloginPasswordData` - Contains the KDF configuration for the user
    pub async fn get_password_prelogin_data(
        &self,
        email: String,
    ) -> Result<PasswordPreloginData, PasswordPreloginError> {
        let request_model = PasswordPreloginRequestModel::new(email);
        let config = self.client.internal.get_api_configurations().await;
        let response = config
            .identity_client
            .accounts_api()
            .post_password_prelogin(Some(request_model))
            .await
            .map_err(ApiError::from)?;

        let prelogin_data = PasswordPreloginData::try_from(response)?;
        Ok(prelogin_data)
    }
}

impl TryFrom<PasswordPreloginResponseModel> for PasswordPreloginData {
    type Error = MissingFieldError;

    fn try_from(response: PasswordPreloginResponseModel) -> Result<Self, Self::Error> {
        use std::num::NonZeroU32;

        use bitwarden_crypto::{
            default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
            default_pbkdf2_iterations,
        };

        let kdf_settings = require!(response.kdf_settings);

        let kdf = match kdf_settings.kdf_type {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: NonZeroU32::new(kdf_settings.iterations as u32)
                    .unwrap_or_else(default_pbkdf2_iterations),
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: NonZeroU32::new(kdf_settings.iterations as u32)
                    .unwrap_or_else(default_argon2_iterations),
                memory: kdf_settings
                    .memory
                    .and_then(|e| NonZeroU32::new(e as u32))
                    .unwrap_or_else(default_argon2_memory),
                parallelism: kdf_settings
                    .parallelism
                    .and_then(|e| NonZeroU32::new(e as u32))
                    .unwrap_or_else(default_argon2_parallelism),
            },
        };

        Ok(PasswordPreloginData {
            kdf,
            salt: require!(response.salt),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_identity::models::{KdfSettings, KdfType, PasswordPreloginResponseModel};
    use bitwarden_crypto::{
        Kdf, default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
        default_pbkdf2_iterations,
    };

    use super::*;

    const TEST_SALT: &str = "test-salt";

    #[test]
    fn test_parse_prelogin_pbkdf2_with_iterations() {
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: 100000,
            memory: None,
            parallelism: None,
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::PBKDF2 {
                iterations: NonZeroU32::new(100000).unwrap()
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }

    #[test]
    fn test_parse_prelogin_pbkdf2_default_iterations() {
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: 0, // Zero will trigger default
            memory: None,
            parallelism: None,
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::PBKDF2 {
                iterations: default_pbkdf2_iterations()
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }

    #[test]
    fn test_parse_prelogin_argon2id_with_all_params() {
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::Argon2id,
            iterations: 4,
            memory: Some(64),
            parallelism: Some(4),
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::Argon2id {
                iterations: NonZeroU32::new(4).unwrap(),
                memory: NonZeroU32::new(64).unwrap(),
                parallelism: NonZeroU32::new(4).unwrap(),
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }

    #[test]
    fn test_parse_prelogin_argon2id_default_params() {
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::Argon2id,
            iterations: 0, // Zero will trigger default
            memory: None,  // None will trigger default
            parallelism: None, // None will trigger default
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::Argon2id {
                iterations: default_argon2_iterations(),
                memory: default_argon2_memory(),
                parallelism: default_argon2_parallelism(),
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }

    #[test]
    fn test_parse_prelogin_missing_kdf_settings() {
        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: None, // Missing kdf_settings
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissingFieldError { .. }));
    }

    #[test]
    fn test_parse_prelogin_missing_salt() {
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: 100000,
            memory: None,
            parallelism: None,
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: None, // Missing salt
        };

        let result = PasswordPreloginData::try_from(response);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissingFieldError { .. }));
    }

    #[test]
    fn test_parse_prelogin_zero_iterations_uses_default() {
        // When the server returns 0, NonZeroU32::new returns None, so defaults should be used
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: 0,
            memory: None,
            parallelism: None,
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::PBKDF2 {
                iterations: default_pbkdf2_iterations()
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }

    #[test]
    fn test_parse_prelogin_argon2id_partial_zero_values() {
        // Test that zero values fall back to defaults for Argon2id
        let kdf_settings = KdfSettings {
            kdf_type: KdfType::Argon2id,
            iterations: 0,    // Zero will trigger default
            memory: Some(0),  // Zero will trigger default
            parallelism: Some(4),
        };

        let response = PasswordPreloginResponseModel {
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: Some(Box::new(kdf_settings)),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = PasswordPreloginData::try_from(response).unwrap();

        assert_eq!(
            result.kdf,
            Kdf::Argon2id {
                iterations: default_argon2_iterations(),
                memory: default_argon2_memory(),
                parallelism: NonZeroU32::new(4).unwrap(),
            }
        );
        assert_eq!(result.salt, TEST_SALT);
    }
}
