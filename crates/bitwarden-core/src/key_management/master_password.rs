//! Master password operations
//!
//! This module contains the data structures and error handling for master password unlock
//! operations.

use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    master_password_unlock_response_model::MasterPasswordUnlockResponseModel, KdfType,
};
use bitwarden_crypto::{CryptoError, EncString, Kdf, MasterKey, SymmetricCryptoKey};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{require, MissingFieldError};

/// Error for master password related operations.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Represents the data required to unlock with the master password.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordUnlockData {
    pub kdf: Kdf,
    pub master_key_wrapped_user_key: EncString,
    pub salt: String,
}

impl MasterPasswordUnlockData {
    pub(crate) fn derive(
        password: &str,
        kdf: &Kdf,
        salt: &String,
        user_key: &SymmetricCryptoKey,
    ) -> Result<Self, MasterPasswordError> {
        let master_key =
            MasterKey::derive(password, salt, kdf).map_err(MasterPasswordError::Crypto)?;
        let master_key_wrapped_user_key = master_key
            .encrypt_user_key(user_key)
            .map_err(MasterPasswordError::Crypto)?;

        Ok(Self {
            kdf: kdf.clone(),
            salt: salt.clone(),
            master_key_wrapped_user_key,
        })
    }
}

impl TryFrom<MasterPasswordUnlockResponseModel> for MasterPasswordUnlockData {
    type Error = MasterPasswordError;

    fn try_from(response: MasterPasswordUnlockResponseModel) -> Result<Self, Self::Error> {
        let kdf = match response.kdf.kdf_type {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: parse_nonzero_u32(
                    response.kdf.iterations,
                    stringify!(response.kdf.iterations),
                )?,
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: parse_nonzero_u32(
                    response.kdf.iterations,
                    stringify!(response.kdf.iterations),
                )?,
                memory: parse_nonzero_u32(
                    require!(response.kdf.memory),
                    stringify!(response.kdf.memory),
                )?,
                parallelism: parse_nonzero_u32(
                    require!(response.kdf.parallelism),
                    stringify!(response.kdf.parallelism),
                )?,
            },
        };

        Ok(MasterPasswordUnlockData {
            kdf,
            master_key_wrapped_user_key: response.master_key_encrypted_user_key.as_str().parse()?,
            salt: response.salt,
        })
    }
}

fn parse_nonzero_u32(
    value: impl TryInto<u32>,
    field_name: &'static str,
) -> Result<NonZeroU32, MissingFieldError> {
    let num: u32 = value
        .try_into()
        .map_err(|_| MissingFieldError(field_name))?;
    NonZeroU32::new(num).ok_or(MissingFieldError(field_name))
}

/// Represents the data required to unlock with the master password.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordAuthenticationData {
    pub kdf: Kdf,
    pub salt: String,
    pub master_password_authentication_hash: String,
}

impl MasterPasswordAuthenticationData {
    pub(crate) fn derive(
        password: &str,
        kdf: &Kdf,
        salt: &String,
    ) -> Result<Self, MasterPasswordError> {
        let master_key =
            MasterKey::derive(password, salt, kdf).map_err(MasterPasswordError::Crypto)?;
        let hash = master_key
            .derive_master_key_hash(
                password.as_bytes(),
                bitwarden_crypto::HashPurpose::ServerAuthorization,
            )
            .map_err(MasterPasswordError::Crypto)?;

        Ok(Self {
            kdf: kdf.clone(),
            salt: salt.clone(),
            master_password_authentication_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockKdfResponseModel};

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_INVALID_USER_KEY: &str = "-1.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=";
    const TEST_SALT: &str = "test@example.com";

    const TEST_PASSWORD: &str = "test_password";
    const TEST_MASTER_PASSWORD_AUTHENTICATION_HASH: &str =
        "Lyry95vlXEJ5FE0EXjeR9zgcsFSU0qGhP9l5X2jwE38=";

    #[test]
    fn test_master_password_unlock_data_derive() {
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        };
        let salt = TEST_SALT.to_string();
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let data = MasterPasswordUnlockData::derive(TEST_PASSWORD, &kdf, &salt, &user_key)
            .expect("Failed to derive master password unlock data");
        assert_eq!(data.salt, salt);
        assert!(matches!(data.kdf, Kdf::PBKDF2 { iterations } if iterations.get() == 600_000));

        let master_key = MasterKey::derive(TEST_PASSWORD, &salt, &data.kdf)
            .expect("Failed to derive master key");
        let decrypted_user_key = master_key
            .decrypt_user_key(data.master_key_wrapped_user_key)
            .expect("Failed to decrypt user key");
        assert_eq!(decrypted_user_key, user_key);
    }

    #[test]
    fn test_master_password_authentication_data_derive() {
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        };
        let salt = TEST_SALT.to_string();
        let data = MasterPasswordAuthenticationData::derive(TEST_PASSWORD, &kdf, &salt)
            .expect("Failed to derive master password authentication data");
        assert_eq!(data.salt, salt);
        assert!(matches!(data.kdf, Kdf::PBKDF2 { iterations } if iterations.get() == 600_000));
        assert_eq!(
            data.master_password_authentication_hash,
            TEST_MASTER_PASSWORD_AUTHENTICATION_HASH
        );
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_pbkdf2_success() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(result.is_ok());
        let data = result.unwrap();

        match data.kdf {
            Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations.get(), 600_000);
            }
            _ => panic!("Expected PBKDF2 KDF"),
        }

        assert_eq!(data.salt, TEST_SALT);
        assert_eq!(data.master_key_wrapped_user_key.to_string(), TEST_USER_KEY);
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_success() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(result.is_ok());
        let data = result.unwrap();

        match data.kdf {
            Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                assert_eq!(iterations.get(), 3);
                assert_eq!(memory.get(), 64);
                assert_eq!(parallelism.get(), 4);
            }
            _ => panic!("Expected Argon2id KDF"),
        }

        assert_eq!(data.salt, TEST_SALT);
        assert_eq!(data.master_key_wrapped_user_key.to_string(), TEST_USER_KEY);
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_invalid_user_key_crypto_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key: TEST_INVALID_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(result, Err(MasterPasswordError::Crypto(_))));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_memory_none_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: None,
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.memory"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_memory_zero_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(0),
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.memory"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_parallelism_none_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: None,
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.parallelism"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_parallelism_zero_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(0),
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.parallelism"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_pbkdf2_iterations_zero_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations: 0,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.iterations"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_iterations_zero_error() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 0,
                memory: Some(64),
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: TEST_USER_KEY.to_string(),
            salt: TEST_SALT.to_string(),
        };

        let result = MasterPasswordUnlockData::try_from(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.iterations"
            )))
        ));
    }

    #[test]
    fn test_serde_serialization_pbkdf2() {
        let data = MasterPasswordUnlockData {
            kdf: Kdf::PBKDF2 {
                iterations: 600_000.try_into().unwrap(),
            },
            master_key_wrapped_user_key: TEST_USER_KEY.parse().unwrap(),
            salt: TEST_SALT.to_string(),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: MasterPasswordUnlockData = serde_json::from_str(&serialized).unwrap();

        match (data.kdf, deserialized.kdf) {
            (Kdf::PBKDF2 { iterations: i1 }, Kdf::PBKDF2 { iterations: i2 }) => {
                assert_eq!(i1, i2);
            }
            _ => panic!("KDF types don't match"),
        }

        assert_eq!(
            data.master_key_wrapped_user_key.to_string(),
            deserialized.master_key_wrapped_user_key.to_string()
        );
        assert_eq!(data.salt, deserialized.salt);
    }

    #[test]
    fn test_serde_serialization_argon2id() {
        let data = MasterPasswordUnlockData {
            kdf: Kdf::Argon2id {
                iterations: 3.try_into().unwrap(),
                memory: 64.try_into().unwrap(),
                parallelism: 4.try_into().unwrap(),
            },
            master_key_wrapped_user_key: TEST_USER_KEY.parse().unwrap(),
            salt: TEST_SALT.to_string(),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: MasterPasswordUnlockData = serde_json::from_str(&serialized).unwrap();

        match (data.kdf, deserialized.kdf) {
            (
                Kdf::Argon2id {
                    iterations: i1,
                    memory: m1,
                    parallelism: p1,
                },
                Kdf::Argon2id {
                    iterations: i2,
                    memory: m2,
                    parallelism: p2,
                },
            ) => {
                assert_eq!(i1, i2);
                assert_eq!(m1, m2);
                assert_eq!(p1, p2);
            }
            _ => panic!("KDF types don't match"),
        }

        assert_eq!(
            data.master_key_wrapped_user_key.to_string(),
            deserialized.master_key_wrapped_user_key.to_string()
        );
        assert_eq!(data.salt, deserialized.salt);
    }
}
