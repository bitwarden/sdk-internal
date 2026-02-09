use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    KdfRequestModel, KdfType, MasterPasswordAuthenticationDataRequestModel,
    MasterPasswordUnlockDataRequestModel,
    master_password_unlock_response_model::MasterPasswordUnlockResponseModel,
};
use bitwarden_crypto::{EncString, Kdf, KeyIds, KeyStoreContext, MasterKey, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use tracing::Level;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{MissingFieldError, require};

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
    /// The KDF had an invalid configuration
    #[error("Invalid KDF configuration")]
    InvalidKdfConfiguration,
    /// The wrapped encryption key or salt fields are missing or KDF data is incomplete
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// Generic crypto error
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    /// The provided password is incorrect
    #[error("Wrong password")]
    WrongPassword,
}

/// Represents the data required to unlock with the master password.
#[derive(Serialize, Deserialize, Debug, Clone)]
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
    pub master_key_wrapped_user_key: EncString,
    /// The salt used in the KDF, typically the user's email
    pub salt: String,
}

impl MasterPasswordUnlockData {
    /// Unwrap the user key into the key store context using the provided password.
    pub fn unwrap_to_context<Ids: KeyIds>(
        &self,
        password: &str,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, MasterPasswordError> {
        let master_key = MasterKey::derive(password, &self.salt, &self.kdf)
            .map_err(|_| MasterPasswordError::InvalidKdfConfiguration)?;
        let user_key = master_key
            .decrypt_user_key(self.master_key_wrapped_user_key.clone())
            .map_err(|_| MasterPasswordError::WrongPassword)?;
        Ok(ctx.add_local_symmetric_key(user_key))
    }

    pub(crate) fn derive_ref(
        password: &str,
        kdf: &Kdf,
        salt: &str,
        user_key: &SymmetricCryptoKey,
    ) -> Result<Self, MasterPasswordError> {
        let master_key = MasterKey::derive(password, salt, kdf)
            .map_err(|_| MasterPasswordError::InvalidKdfConfiguration)?;
        let master_key_wrapped_user_key = master_key
            .encrypt_user_key(user_key)
            .map_err(MasterPasswordError::Crypto)?;

        Ok(Self {
            kdf: kdf.to_owned(),
            salt: salt.to_owned(),
            master_key_wrapped_user_key,
        })
    }

    /// Derive master password unlock data from a password and user key in the key store.
    #[tracing::instrument(skip(password, salt, ctx))]
    pub fn derive<Ids: KeyIds>(
        password: &str,
        kdf: &Kdf,
        salt: &str,
        user_key_id: Ids::Symmetric,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, MasterPasswordError> {
        tracing::event!(Level::INFO, "deriving master password unlock data");
        // Temporary workaround until lower level functions also work on the key context
        #[expect(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(user_key_id)?;
        Self::derive_ref(password, kdf, salt, key)
    }
}

impl TryFrom<&MasterPasswordUnlockResponseModel> for MasterPasswordUnlockData {
    type Error = MasterPasswordError;

    fn try_from(response: &MasterPasswordUnlockResponseModel) -> Result<Self, Self::Error> {
        let kdf = match response.kdf.kdf_type {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: kdf_parse_nonzero_u32(response.kdf.iterations)?,
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: kdf_parse_nonzero_u32(response.kdf.iterations)?,
                memory: kdf_parse_nonzero_u32(require!(response.kdf.memory))?,
                parallelism: kdf_parse_nonzero_u32(require!(response.kdf.parallelism))?,
            },
            KdfType::__Unknown(_) => return Err(MissingFieldError("kdf").into()),
        };

        let master_key_wrapped_user_key = require!(&response.master_key_encrypted_user_key)
            .parse()
            .map_err(|_| MasterPasswordError::EncryptionKeyMalformed)?;
        let salt = require!(&response.salt).clone();

        Ok(MasterPasswordUnlockData {
            kdf,
            master_key_wrapped_user_key,
            salt,
        })
    }
}

impl From<&MasterPasswordUnlockData> for MasterPasswordUnlockDataRequestModel {
    fn from(data: &MasterPasswordUnlockData) -> Self {
        Self {
            kdf: Box::new(kdf_to_kdf_request_model(&data.kdf)),
            master_key_wrapped_user_key: data.master_key_wrapped_user_key.to_string(),
            salt: data.salt.to_owned(),
        }
    }
}

fn kdf_parse_nonzero_u32(value: impl TryInto<u32>) -> Result<NonZeroU32, MasterPasswordError> {
    value
        .try_into()
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(MasterPasswordError::KdfMalformed)
}

/// Represents the data required to authenticate with the master password.
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
    pub master_password_authentication_hash: B64,
}

impl MasterPasswordAuthenticationData {
    /// Derive master password authentication data from a password, KDF, and salt.
    #[tracing::instrument(skip(password, kdf, salt))]
    pub fn derive(password: &str, kdf: &Kdf, salt: &str) -> Result<Self, MasterPasswordError> {
        tracing::event!(Level::INFO, "deriving master password authentication data");
        let master_key = MasterKey::derive(password, salt, kdf)
            .map_err(|_| MasterPasswordError::InvalidKdfConfiguration)?;
        let hash = master_key.derive_master_key_hash(
            password.as_bytes(),
            bitwarden_crypto::HashPurpose::ServerAuthorization,
        );

        Ok(Self {
            kdf: kdf.to_owned(),
            salt: salt.to_owned(),
            master_password_authentication_hash: hash,
        })
    }
}

impl From<&MasterPasswordAuthenticationData> for MasterPasswordAuthenticationDataRequestModel {
    fn from(data: &MasterPasswordAuthenticationData) -> Self {
        Self {
            kdf: Box::new(kdf_to_kdf_request_model(&data.kdf)),
            master_password_authentication_hash: data
                .master_password_authentication_hash
                .to_string(),
            salt: data.salt.to_owned(),
        }
    }
}

fn kdf_to_kdf_request_model(kdf: &Kdf) -> KdfRequestModel {
    match kdf {
        Kdf::PBKDF2 { iterations } => KdfRequestModel {
            kdf_type: KdfType::PBKDF2_SHA256,
            iterations: iterations.get() as i32,
            memory: None,
            parallelism: None,
        },
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => KdfRequestModel {
            kdf_type: KdfType::Argon2id,
            iterations: iterations.get() as i32,
            memory: Some(memory.get() as i32),
            parallelism: Some(parallelism.get() as i32),
        },
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockKdfResponseModel};
    use bitwarden_crypto::KeyStore;

    use super::*;
    use crate::key_management::{KeyIds, SymmetricKeyId};

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
        let data = MasterPasswordUnlockData::derive_ref(TEST_PASSWORD, &kdf, &salt, &user_key)
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
            data.master_password_authentication_hash.to_string(),
            TEST_MASTER_PASSWORD_AUTHENTICATION_HASH
        );
    }

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
    fn test_try_from_master_password_unlock_response_model_invalid_user_key_encryption_kdf_malformed_error()
     {
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
                "&response.master_key_encrypted_user_key"
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
                "&response.salt"
            )))
        ));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_memory_none_missing_field_error()
     {
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
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_memory_zero_kdf_malformed_error()
     {
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
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_parallelism_none_missing_field_error()
     {
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
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_parallelism_zero_kdf_malformed_error()
     {
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
    fn test_try_from_master_password_unlock_response_model_pbkdf2_kdf_iterations_zero_kdf_malformed_error()
     {
        let response = create_pbkdf2_response(
            Some(TEST_USER_KEY.to_string()),
            Some(TEST_SALT.to_string()),
            0,
        );

        let result = MasterPasswordUnlockData::try_from(&response);
        assert!(matches!(result, Err(MasterPasswordError::KdfMalformed)));
    }

    #[test]
    fn test_try_from_master_password_unlock_response_model_argon2id_kdf_iterations_zero_kdf_malformed_error()
     {
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

    #[test]
    fn test_unwrap_to_context_success() {
        // Derive master password unlock data from a known password and user key
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).expect("non-zero"),
        };
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let data = MasterPasswordUnlockData::derive_ref(TEST_PASSWORD, &kdf, TEST_SALT, &user_key)
            .expect("Failed to derive master password unlock data");

        // Create a key store and unwrap the user key into the context
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let key_id = data
            .unwrap_to_context::<KeyIds>(TEST_PASSWORD, &mut ctx)
            .expect("Failed to unwrap to context");

        // Verify that the key was added to the context
        assert!(ctx.has_symmetric_key(key_id));

        // Verify the unwrapped key matches the original
        #[expect(deprecated)]
        let unwrapped_key = ctx
            .dangerous_get_symmetric_key(key_id)
            .expect("Failed to get symmetric key");
        assert_eq!(*unwrapped_key, user_key);
    }

    #[test]
    fn test_unwrap_to_context_wrong_password() {
        // Derive master password unlock data from a known password and user key
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).expect("non-zero"),
        };
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let data = MasterPasswordUnlockData::derive_ref(TEST_PASSWORD, &kdf, TEST_SALT, &user_key)
            .expect("Failed to derive master password unlock data");

        // Attempt to unwrap with wrong password
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let result = data.unwrap_to_context::<KeyIds>("wrong_password", &mut ctx);

        assert!(matches!(result, Err(MasterPasswordError::WrongPassword)));
    }

    #[test]
    fn test_unwrap_to_context_persists_key() {
        // Derive master password unlock data from a known password and user key
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).expect("non-zero"),
        };
        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let data = MasterPasswordUnlockData::derive_ref(TEST_PASSWORD, &kdf, TEST_SALT, &user_key)
            .expect("Failed to derive master password unlock data");

        // Create a key store and unwrap the user key into the context
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = data
                .unwrap_to_context::<KeyIds>(TEST_PASSWORD, &mut ctx)
                .expect("Failed to unwrap to context");

            // Persist the local key to the User key slot
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .expect("Failed to persist symmetric key");
        }

        // Verify the key is accessible with the User key id in a new context
        let ctx = store.context();
        assert!(ctx.has_symmetric_key(SymmetricKeyId::User));
    }
}
