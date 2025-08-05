#![allow(missing_docs)]

use bitwarden_core::key_management::user_decryption::{UserDecryptionData, UserDecryptionError};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use crate::key_management::master_password::MasterPasswordUnlockResponseModel;

// WASM-compatible wrapper for the auto-generated UserDecryptionResponseModel
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct UserDecryptionResponseModel {
    #[serde(alias = "MasterPasswordUnlock")]
    pub master_password_unlock: Option<MasterPasswordUnlockResponseModel>,
}

impl From<UserDecryptionResponseModel> for bitwarden_api_api::models::UserDecryptionResponseModel {
    fn from(wasm_model: UserDecryptionResponseModel) -> Self {
        bitwarden_api_api::models::UserDecryptionResponseModel {
            master_password_unlock: wasm_model
                .master_password_unlock
                .map(|master_password_unlock| Box::new(master_password_unlock.into())),
        }
    }
}

/// WASM-exposed function to process a UserDecryptionResponseModel
#[wasm_bindgen]
pub fn process_user_decryption_response(
    response: UserDecryptionResponseModel,
) -> Result<UserDecryptionData, UserDecryptionError> {
    let api_response: bitwarden_api_api::models::UserDecryptionResponseModel = response.into();

    UserDecryptionData::process_response(api_response)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::KdfType;
    use bitwarden_core::{key_management::master_password::MasterPasswordError, MissingFieldError};

    use super::*;
    use crate::key_management::master_password::MasterPasswordUnlockKdfResponseModel;

    const TEST_USER_KEY: &str = "2.Dh7AFLXR+LXcxUaO5cRjpg==|uXyhubjAoNH8lTdy/zgJDQ==|cHEMboj0MYsU5yDRQ1rLCgxcjNbKRc1PWKuv8bpU5pM=";
    const TEST_SALT: &str = "test@example.com";

    #[test]
    fn test_process_user_decryption_response_some() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600_000,
                    memory: None,
                    parallelism: None,
                },
                master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
                salt: Some(TEST_SALT.to_string()),
            }),
        };

        let result = process_user_decryption_response(response);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert!(data.master_password_unlock.is_some());

        let master_password_unlock = data.master_password_unlock.unwrap();

        match master_password_unlock.kdf {
            bitwarden_crypto::Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations.get(), 600_000);
            }
            _ => panic!("Expected PBKDF2 KDF"),
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
    fn test_process_user_decryption_response_none() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: None,
        };

        let result = process_user_decryption_response(response);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert!(data.master_password_unlock.is_none());
    }

    #[test]
    fn test_process_user_decryption_response_missing_salt() {
        let response = UserDecryptionResponseModel {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600_000,
                    memory: None,
                    parallelism: None,
                },
                master_key_encrypted_user_key: Some(TEST_USER_KEY.to_string()),
                salt: None,
            }),
        };

        let result = process_user_decryption_response(response);
        assert!(matches!(
            result,
            Err(UserDecryptionError::MasterPasswordError(
                MasterPasswordError::MissingField(MissingFieldError("response.salt"))
            ))
        ));
    }
}
