#![allow(missing_docs)]

use bitwarden_api_api::models::UserDecryptionResponseModel;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::key_management::master_password::{MasterPasswordError, MasterPasswordUnlockData};

#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum UserDecryptionError {
    #[error(transparent)]
    MasterPasswordError(#[from] MasterPasswordError),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct UserDecryptionData {
    pub master_password_unlock: Option<MasterPasswordUnlockData>,
}

impl TryFrom<UserDecryptionResponseModel> for UserDecryptionData {
    type Error = UserDecryptionError;

    fn try_from(response: UserDecryptionResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .map(|response| MasterPasswordUnlockData::try_from(*response))
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockResponseModel};
    use bitwarden_crypto::Kdf;

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_SALT: &str = "test@example.com";

    #[test]
    fn test_process_response_master_password_unlock_some() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(MasterPasswordUnlockResponseModel {
                kdf: Box::new(
                    bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel {
                        kdf_type: KdfType::Argon2id,
                        iterations: 3,
                        memory: Some(64),
                        parallelism: Some(4),
                    },
                ),
                master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
                salt: Some(TEST_SALT.to_string()),
            })),
        };

        let result = UserDecryptionData::process_response(response);
        assert!(result.is_ok());

        let user_decryption_data = result.unwrap();

        assert!(user_decryption_data.master_password_unlock.is_some());

        let master_password_unlock = user_decryption_data.master_password_unlock.unwrap();

        match master_password_unlock.kdf {
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

        assert_eq!(master_password_unlock.salt, TEST_SALT);
        assert_eq!(
            master_password_unlock
                .master_key_wrapped_user_key
                .to_string(),
            TEST_USER_KEY
        );
    }

    #[test]
    fn test_process_response_missing_master_password_unlock() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: None,
        };

        let result = UserDecryptionData::process_response(response);
        assert!(result.is_ok());

        let user_decryption_data = result.unwrap();

        assert!(user_decryption_data.master_password_unlock.is_none());
    }

    #[test]
    fn test_process_response_missing_master_password_unlock_salt() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(MasterPasswordUnlockResponseModel {
                kdf: Box::new(
                    bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel {
                        kdf_type: KdfType::Argon2id,
                        iterations: 3,
                        memory: Some(64),
                        parallelism: Some(4),
                    },
                ),
                master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
                salt: None,
            })),
        };

        let result = UserDecryptionData::process_response(response);
        assert!(matches!(
            result,
            Err(UserDecryptionError::MasterPasswordError(
                MasterPasswordError::MissingField(_)
            ))
        ));
    }
}
