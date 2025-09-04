use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    master_password_unlock_response_model::MasterPasswordUnlockResponseModel, KdfType,
};
use bitwarden_crypto::{EncString, Kdf};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};

use crate::{require, MissingFieldError};

/// Error for master password related operations.
#[allow(dead_code)]
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    /// The wrapped encryption key could not be parsed because the encstring is malformed
    #[error("Wrapped encryption key is malformed")]
    EncryptionKeyMalformed,
    /// The KDF data could not be parsed, because it has an invalid value
    #[error("KDF is malformed")]
    KdfMalformed,
    /// The wrapped encryption key or salt fields are missing or KDF data is incomplete
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Represents the data required to unlock with the master password.
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordUnlockData {
    /// The key derivation function used to derive the master key
    pub kdf: Kdf,
    /// The master key wrapped user key
    pub(crate) master_key_wrapped_user_key: EncString,
    /// The salt used in the KDF, typically the user's email
    pub(crate) salt: String,
}

impl TryFrom<&MasterPasswordUnlockResponseModel> for MasterPasswordUnlockData {
    type Error = MasterPasswordError;

    fn try_from(response: &MasterPasswordUnlockResponseModel) -> Result<Self, Self::Error> {
        let response = response.clone();

        let kdf = match response.kdf.kdf_type {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: kdf_parse_nonzero_u32(response.kdf.iterations)?,
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: kdf_parse_nonzero_u32(response.kdf.iterations)?,
                memory: kdf_parse_nonzero_u32(require!(response.kdf.memory))?,
                parallelism: kdf_parse_nonzero_u32(require!(response.kdf.parallelism))?,
            },
        };

        let master_key_encrypted_user_key = require!(response.master_key_encrypted_user_key);
        let salt = require!(response.salt);

        Ok(MasterPasswordUnlockData {
            kdf,
            master_key_wrapped_user_key: master_key_encrypted_user_key
                .parse()
                .map_err(|_| MasterPasswordError::EncryptionKeyMalformed)?,
            salt,
        })
    }
}

fn kdf_parse_nonzero_u32(value: impl TryInto<u32>) -> Result<NonZeroU32, MasterPasswordError> {
    value
        .try_into()
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(MasterPasswordError::KdfMalformed)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockKdfResponseModel};

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_INVALID_USER_KEY: &str = "-1.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=";
    const TEST_SALT: &str = "test@example.com";

    fn create_pbkdf2_response(
        master_key_encrypted_user_key: Option<String>,
        salt: Option<String>,
        iterations: i32,
    ) -> MasterPasswordUnlockResponseModel {
        MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key,
            salt,
        }
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_pbkdf2_success() {
        let response = create_pbkdf2_response(
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
            600_000,
        );

        let data = MasterPasswordUnlockData::try_from(&response).unwrap();

        if let Kdf::PBKDF2 { iterations } = data.kdf {
            assert_eq!(iterations.get(), 600_000);
        } else {
            panic!("Expected PBKDF2 KDF")
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
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let data = MasterPasswordUnlockData::try_from(&response).unwrap();

        if let Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } = data.kdf
        {
            assert_eq!(iterations.get(), 3);
            assert_eq!(memory.get(), 64);
            assert_eq!(parallelism.get(), 4);
        } else {
            panic!("Expected Argon2id KDF")
        }

        assert_eq!(data.salt, TEST_SALT);
        assert_eq!(data.master_key_wrapped_user_key.to_string(), TEST_USER_KEY);
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_invalid_user_key_encryption_kdf_malformed_error(
    ) {
        let response = create_pbkdf2_response(
            Some(TEST_INVALID_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
            600_000,
        );

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::EncryptionKeyMalformed)
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_user_key_none_missing_field_error() {
        let response = create_pbkdf2_response(None, Some(TEST_SALT.to_string()), 600_000);

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.master_key_encrypted_user_key"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_salt_none_missing_field_error() {
        let response = create_pbkdf2_response(Some(TEST_USER_KEY.to_string()), None, 600_000);

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.salt"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_memory_none_missing_field_error(
    ) {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: None,
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.memory"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_memory_zero_kdf_malformed_error(
    ) {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(0),
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(result, Err(MasterPasswordError::KdfMalformed)));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_parallelism_none_missing_field_error(
    ) {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: None,
            }),
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(
            result,
            Err(MasterPasswordError::MissingField(MissingFieldError(
                "response.kdf.parallelism"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_parallelism_zero_kdf_malformed_error(
    ) {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(0),
            }),
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(result, Err(MasterPasswordError::KdfMalformed)));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_pbkdf2_kdf_iterations_zero_kdf_malformed_error(
    ) {
        let response = create_pbkdf2_response(
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
            0,
        );

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(result, Err(MasterPasswordError::KdfMalformed)));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_iterations_zero_kdf_malformed_error(
    ) {
        let response = MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 0,
                memory: Some(64),
                parallelism: Some(4),
            }),
            master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
            salt: Some(TEST_SALT.to_string()),
        };

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(result, Err(MasterPasswordError::KdfMalformed)));
    }
}
