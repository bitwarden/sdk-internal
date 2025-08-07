#![allow(missing_docs)]

use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    master_password_unlock_response_model::MasterPasswordUnlockResponseModel, KdfType,
};
use bitwarden_crypto::{CryptoError, EncString, Kdf};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{require, MissingFieldError};

#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

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

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockKdfResponseModel};

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_INVALID_USER_KEY: &str = "-1.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=";
    const TEST_SALT: &str = "test@example.com";

    fn create_pbkdf2_response(
        iterations: i32,
        encrypted_user_key: Option<String>,
        salt: Option<String>,
    ) -> MasterPasswordUnlockResponseModel {
        MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key: encrypted_user_key,
            salt,
        }
    }

    fn create_argon2id_response(
        iterations: i32,
        memory: Option<i32>,
        parallelism: Option<i32>,
        encrypted_user_key: Option<String>,
        salt: Option<String>,
    ) -> MasterPasswordUnlockResponseModel {
        MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations,
                memory,
                parallelism,
            }),
            master_key_encrypted_user_key: encrypted_user_key,
            salt,
        }
    }

    #[test]
    fn test_process_response_pbkdf2_success() {
        let response = create_pbkdf2_response(
            600_000,
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response).unwrap();

        match result.kdf {
            Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations.get(), 600_000);
            }
            _ => panic!("Expected PBKDF2 KDF"),
        }

        assert_eq!(result.salt, TEST_SALT);
        assert_eq!(
            result.master_key_wrapped_user_key.to_string(),
            TEST_USER_KEY
        );
    }

    #[test]
    fn test_process_response_argon2id_success() {
        let response = create_argon2id_response(
            3,
            Some(64),
            Some(4),
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response).unwrap();

        match result.kdf {
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

        assert_eq!(result.salt, TEST_SALT);
        assert_eq!(
            result.master_key_wrapped_user_key.to_string(),
            TEST_USER_KEY
        );
    }

    #[test]
    fn test_process_response_invalid_user_key_crypto_error() {
        let response = create_pbkdf2_response(
            600_000,
            Some(TEST_INVALID_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(result, Err(MasterPasswordError::Crypto(_))));
    }

    #[test]
    fn test_process_response_missing_encrypted_user_key() {
        let response = create_pbkdf2_response(600_000, None, Some(TEST_SALT.to_string()));

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.master_key_encrypted_user_key"
            )))
        ));
    }

    #[test]
    fn test_process_response_missing_salt() {
        let response = create_pbkdf2_response(600_000, Some(TEST_USER_KEY.to_string()), None);

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.salt"
            )))
        ));
    }

    #[test]
    fn test_process_response_argon2id_missing_memory() {
        let response = create_argon2id_response(
            3,
            None,
            Some(4),
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.memory"
            )))
        ));
    }

    #[test]
    fn test_process_response_argon2id_missing_parallelism() {
        let response = create_argon2id_response(
            3,
            Some(64),
            None,
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.parallelism"
            )))
        ));
    }

    #[test]
    fn test_process_response_zero_iterations_pbkdf2() {
        let response = create_pbkdf2_response(
            0,
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.iterations"
            )))
        ));
    }

    #[test]
    fn test_process_response_zero_iterations_argon2id() {
        let response = create_argon2id_response(
            0,
            Some(0),
            Some(0),
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
        );

        let result = MasterPasswordUnlockData::process_response(response);
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
