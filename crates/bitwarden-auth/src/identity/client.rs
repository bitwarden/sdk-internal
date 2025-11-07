use bitwarden_api_identity::models::{PreloginRequestModel, PreloginResponseModel};
use bitwarden_core::{ApiError, Client, MissingFieldError, require};
use bitwarden_crypto::Kdf;
use bitwarden_error::bitwarden_error;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The IdentityClient is used to obtain identity / access tokens from the Bitwarden Identity API.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct IdentityClient {
    pub(crate) client: Client,
}

impl IdentityClient {
    /// Create a new IdentityClient with the given Client.
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

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
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct PasswordPreloginData {
    /// The Key Derivation Function (KDF) configuration for the user
    pub kdf: Kdf,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl IdentityClient {
    /// Retrieves the data required before authenticating with a password.
    /// This includes the user's KDF configuration needed to properly derive the master key.
    ///
    /// # Arguments
    /// * `email` - The user's email address
    ///
    /// # Returns
    /// * `PasswordPreloginData` - Contains the KDF configuration for the user
    pub async fn get_password_prelogin_data(
        &self,
        email: String,
    ) -> Result<PasswordPreloginData, PasswordPreloginError> {
        let request_model = PreloginRequestModel::new(email);
        let config = self.client.internal.get_api_configurations().await;
        let response = config
            .identity_client
            .accounts_api()
            .post_prelogin(Some(request_model))
            .await
            .map_err(ApiError::from)?;

        let kdf = parse_password_prelogin_response(response)?;
        Ok(PasswordPreloginData { kdf })
    }
}

/// Parses the password prelogin API response into a KDF configuration
fn parse_password_prelogin_response(
    response: PreloginResponseModel,
) -> Result<Kdf, MissingFieldError> {
    use std::num::NonZeroU32;

    use bitwarden_api_identity::models::KdfType;
    use bitwarden_crypto::{
        default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
        default_pbkdf2_iterations,
    };

    let kdf = require!(response.kdf);

    Ok(match kdf {
        KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: response
                .kdf_iterations
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_pbkdf2_iterations),
        },
        KdfType::Argon2id => Kdf::Argon2id {
            iterations: response
                .kdf_iterations
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_iterations),
            memory: response
                .kdf_memory
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_memory),
            parallelism: response
                .kdf_parallelism
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_parallelism),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_client_creation() {
        let client: Client = Client::new(None);
        let identity_client = IdentityClient::new(client);

        // Verify the identity client was created successfully
        // The client field is present and accessible
        let _ = identity_client.client;
    }

    mod get_password_prelogin_data {
        use std::num::NonZeroU32;

        use bitwarden_api_identity::models::{KdfType, PreloginResponseModel};
        use bitwarden_crypto::{
            Kdf, default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
            default_pbkdf2_iterations,
        };

        use super::*;

        #[test]
        fn test_parse_prelogin_pbkdf2_with_iterations() {
            let response = PreloginResponseModel {
                kdf: Some(KdfType::PBKDF2_SHA256),
                kdf_iterations: Some(100000),
                kdf_memory: None,
                kdf_parallelism: None,
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::PBKDF2 {
                    iterations: NonZeroU32::new(100000).unwrap()
                }
            );
        }

        #[test]
        fn test_parse_prelogin_pbkdf2_default_iterations() {
            let response = PreloginResponseModel {
                kdf: Some(KdfType::PBKDF2_SHA256),
                kdf_iterations: None,
                kdf_memory: None,
                kdf_parallelism: None,
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::PBKDF2 {
                    iterations: default_pbkdf2_iterations()
                }
            );
        }

        #[test]
        fn test_parse_prelogin_argon2id_with_all_params() {
            let response = PreloginResponseModel {
                kdf: Some(KdfType::Argon2id),
                kdf_iterations: Some(4),
                kdf_memory: Some(64),
                kdf_parallelism: Some(4),
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::Argon2id {
                    iterations: NonZeroU32::new(4).unwrap(),
                    memory: NonZeroU32::new(64).unwrap(),
                    parallelism: NonZeroU32::new(4).unwrap(),
                }
            );
        }

        #[test]
        fn test_parse_prelogin_argon2id_default_params() {
            let response = PreloginResponseModel {
                kdf: Some(KdfType::Argon2id),
                kdf_iterations: None,
                kdf_memory: None,
                kdf_parallelism: None,
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::Argon2id {
                    iterations: default_argon2_iterations(),
                    memory: default_argon2_memory(),
                    parallelism: default_argon2_parallelism(),
                }
            );
        }

        #[test]
        fn test_parse_prelogin_missing_kdf_type() {
            let response = PreloginResponseModel {
                kdf: None,
                kdf_iterations: Some(100000),
                kdf_memory: None,
                kdf_parallelism: None,
            };

            let result = parse_password_prelogin_response(response);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), MissingFieldError { .. }));
        }

        #[test]
        fn test_parse_prelogin_zero_iterations_uses_default() {
            // When the server returns 0, NonZeroU32::new returns None, so defaults should be used
            let response = PreloginResponseModel {
                kdf: Some(KdfType::PBKDF2_SHA256),
                kdf_iterations: Some(0),
                kdf_memory: None,
                kdf_parallelism: None,
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::PBKDF2 {
                    iterations: default_pbkdf2_iterations()
                }
            );
        }

        #[test]
        fn test_parse_prelogin_argon2id_partial_zero_values() {
            // Test that zero values fall back to defaults for Argon2id
            let response = PreloginResponseModel {
                kdf: Some(KdfType::Argon2id),
                kdf_iterations: Some(0),
                kdf_memory: Some(0),
                kdf_parallelism: Some(4),
            };

            let result = parse_password_prelogin_response(response).unwrap();

            assert_eq!(
                result,
                Kdf::Argon2id {
                    iterations: default_argon2_iterations(),
                    memory: default_argon2_memory(),
                    parallelism: NonZeroU32::new(4).unwrap(),
                }
            );
        }
    }
}
