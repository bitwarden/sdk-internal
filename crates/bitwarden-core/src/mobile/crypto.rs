use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use bitwarden_crypto::{
    AsymmetricCryptoKey, AsymmetricEncString, CryptoError, EncString, Kdf, KeyDecryptable,
    KeyEncryptable, MasterKey, SymmetricCryptoKey, UserKey,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

use crate::{
    client::{encryption_settings::EncryptionSettingsError, LoginMethod, UserLoginMethod},
    error::{NotAuthenticatedError, Result},
    Client, VaultLockedError, WrongPasswordError,
};

/// Catch all errors for mobile crypto operations
#[derive(Debug, thiserror::Error)]
pub enum MobileCryptoError {
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    VaultLocked(#[from] VaultLockedError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct InitUserCryptoRequest {
    /// The user's KDF parameters, as received from the prelogin request
    pub kdf_params: Kdf,
    /// The user's email address
    pub email: String,
    /// The user's encrypted private key
    pub private_key: String,
    /// The initialization method to use
    pub method: InitUserCryptoMethod,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum InitUserCryptoMethod {
    Password {
        /// The user's master password
        password: String,
        /// The user's encrypted symmetric crypto key
        user_key: String,
    },
    DecryptedKey {
        /// The user's decrypted encryption key, obtained using `get_user_encryption_key`
        decrypted_user_key: String,
    },
    Pin {
        /// The user's PIN
        pin: String,
        /// The user's symmetric crypto key, encrypted with the PIN. Use `derive_pin_key` to obtain
        /// this.
        pin_protected_user_key: EncString,
    },
    AuthRequest {
        /// Private Key generated by the `crate::auth::new_auth_request`.
        request_private_key: String,

        method: AuthRequestMethod,
    },
    DeviceKey {
        /// The device's DeviceKey
        device_key: String,
        /// The Device Private Key
        protected_device_private_key: EncString,
        /// The user's symmetric crypto key, encrypted with the Device Key.
        device_protected_user_key: AsymmetricEncString,
    },
    KeyConnector {
        /// Base64 encoded master key, retrieved from the key connector.
        master_key: String,
        /// The user's encrypted symmetric crypto key
        user_key: String,
    },
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum AuthRequestMethod {
    UserKey {
        /// User Key protected by the private key provided in `AuthRequestResponse`.
        protected_user_key: AsymmetricEncString,
    },
    MasterKey {
        /// Master Key protected by the private key provided in `AuthRequestResponse`.
        protected_master_key: AsymmetricEncString,
        /// User Key protected by the MasterKey, provided by the auth response.
        auth_request_key: EncString,
    },
}

pub async fn initialize_user_crypto(
    client: &Client,
    req: InitUserCryptoRequest,
) -> Result<(), EncryptionSettingsError> {
    use bitwarden_crypto::{DeviceKey, PinKey};

    use crate::auth::{auth_request_decrypt_master_key, auth_request_decrypt_user_key};

    let private_key: EncString = req.private_key.parse()?;

    match req.method {
        InitUserCryptoMethod::Password { password, user_key } => {
            let user_key: EncString = user_key.parse()?;

            let master_key = MasterKey::derive(&password, &req.email, &req.kdf_params)?;
            client
                .internal
                .initialize_user_crypto_master_key(master_key, user_key, private_key)?;
        }
        InitUserCryptoMethod::DecryptedKey { decrypted_user_key } => {
            let user_key = SymmetricCryptoKey::try_from(decrypted_user_key)?;
            client
                .internal
                .initialize_user_crypto_decrypted_key(user_key, private_key)?;
        }
        InitUserCryptoMethod::Pin {
            pin,
            pin_protected_user_key,
        } => {
            let pin_key = PinKey::derive(pin.as_bytes(), req.email.as_bytes(), &req.kdf_params)?;
            client.internal.initialize_user_crypto_pin(
                pin_key,
                pin_protected_user_key,
                private_key,
            )?;
        }
        InitUserCryptoMethod::AuthRequest {
            request_private_key,
            method,
        } => {
            let user_key = match method {
                AuthRequestMethod::UserKey { protected_user_key } => {
                    auth_request_decrypt_user_key(request_private_key, protected_user_key)?
                }
                AuthRequestMethod::MasterKey {
                    protected_master_key,
                    auth_request_key,
                } => auth_request_decrypt_master_key(
                    request_private_key,
                    protected_master_key,
                    auth_request_key,
                )?,
            };
            client
                .internal
                .initialize_user_crypto_decrypted_key(user_key, private_key)?;
        }
        InitUserCryptoMethod::DeviceKey {
            device_key,
            protected_device_private_key,
            device_protected_user_key,
        } => {
            let device_key = DeviceKey::try_from(device_key)?;
            let user_key = device_key
                .decrypt_user_key(protected_device_private_key, device_protected_user_key)?;

            client
                .internal
                .initialize_user_crypto_decrypted_key(user_key, private_key)?;
        }
        InitUserCryptoMethod::KeyConnector {
            master_key,
            user_key,
        } => {
            let mut master_key_bytes = STANDARD
                .decode(master_key)
                .map_err(|_| CryptoError::InvalidKey)?;
            let master_key = MasterKey::try_from(master_key_bytes.as_mut_slice())?;
            let user_key: EncString = user_key.parse()?;

            client
                .internal
                .initialize_user_crypto_master_key(master_key, user_key, private_key)?;
        }
    }

    client
        .internal
        .set_login_method(crate::client::LoginMethod::User(
            crate::client::UserLoginMethod::Username {
                client_id: "".to_string(),
                email: req.email,
                kdf: req.kdf_params,
            },
        ));

    Ok(())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct InitOrgCryptoRequest {
    /// The encryption keys for all the organizations the user is a part of
    pub organization_keys: HashMap<uuid::Uuid, AsymmetricEncString>,
}

pub async fn initialize_org_crypto(
    client: &Client,
    req: InitOrgCryptoRequest,
) -> Result<(), EncryptionSettingsError> {
    let organization_keys = req.organization_keys.into_iter().collect();
    client.internal.initialize_org_crypto(organization_keys)?;
    Ok(())
}

pub async fn get_user_encryption_key(client: &Client) -> Result<String, MobileCryptoError> {
    let enc = client.internal.get_encryption_settings()?;
    let user_key = enc.get_key(&None)?;

    Ok(user_key.to_base64())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct UpdatePasswordResponse {
    /// Hash of the new password
    password_hash: String,
    /// User key, encrypted with the new password
    new_key: EncString,
}

pub fn update_password(
    client: &Client,
    new_password: String,
) -> Result<UpdatePasswordResponse, MobileCryptoError> {
    let enc = client.internal.get_encryption_settings()?;
    let user_key = enc.get_key(&None)?;

    let login_method = client
        .internal
        .get_login_method()
        .ok_or(NotAuthenticatedError)?;

    // Derive a new master key from password
    let new_master_key = match login_method.as_ref() {
        LoginMethod::User(
            UserLoginMethod::Username { email, kdf, .. }
            | UserLoginMethod::ApiKey { email, kdf, .. },
        ) => MasterKey::derive(&new_password, email, kdf)?,
        #[cfg(feature = "secrets")]
        LoginMethod::ServiceAccount(_) => return Err(NotAuthenticatedError)?,
    };

    let new_key = new_master_key.encrypt_user_key(user_key)?;

    let password_hash = new_master_key.derive_master_key_hash(
        new_password.as_bytes(),
        bitwarden_crypto::HashPurpose::ServerAuthorization,
    )?;

    Ok(UpdatePasswordResponse {
        password_hash,
        new_key,
    })
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DerivePinKeyResponse {
    /// [UserKey](bitwarden_crypto::UserKey) protected by PIN
    pin_protected_user_key: EncString,
    /// PIN protected by [UserKey](bitwarden_crypto::UserKey)
    encrypted_pin: EncString,
}

pub fn derive_pin_key(
    client: &Client,
    pin: String,
) -> Result<DerivePinKeyResponse, MobileCryptoError> {
    let enc = client.internal.get_encryption_settings()?;
    let user_key = enc.get_key(&None)?;

    let login_method = client
        .internal
        .get_login_method()
        .ok_or(NotAuthenticatedError)?;

    let pin_protected_user_key = derive_pin_protected_user_key(&pin, &login_method, user_key)?;

    Ok(DerivePinKeyResponse {
        pin_protected_user_key,
        encrypted_pin: pin.encrypt_with_key(user_key)?,
    })
}

pub fn derive_pin_user_key(
    client: &Client,
    encrypted_pin: EncString,
) -> Result<EncString, MobileCryptoError> {
    let enc = client.internal.get_encryption_settings()?;
    let user_key = enc.get_key(&None)?;

    let pin: String = encrypted_pin.decrypt_with_key(user_key)?;
    let login_method = client
        .internal
        .get_login_method()
        .ok_or(NotAuthenticatedError)?;

    derive_pin_protected_user_key(&pin, &login_method, user_key)
}

fn derive_pin_protected_user_key(
    pin: &str,
    login_method: &LoginMethod,
    user_key: &SymmetricCryptoKey,
) -> Result<EncString, MobileCryptoError> {
    use bitwarden_crypto::PinKey;

    let derived_key = match login_method {
        LoginMethod::User(
            UserLoginMethod::Username { email, kdf, .. }
            | UserLoginMethod::ApiKey { email, kdf, .. },
        ) => PinKey::derive(pin.as_bytes(), email.as_bytes(), kdf)?,
        #[cfg(feature = "secrets")]
        LoginMethod::ServiceAccount(_) => return Err(NotAuthenticatedError)?,
    };

    Ok(derived_key.encrypt_user_key(user_key)?)
}

/// Catch all errors for mobile crypto operations
#[derive(Debug, thiserror::Error)]
pub enum EnrollAdminPasswordResetError {
    #[error(transparent)]
    VaultLocked(#[from] VaultLockedError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),
}

pub(super) fn enroll_admin_password_reset(
    client: &Client,
    public_key: String,
) -> Result<AsymmetricEncString, EnrollAdminPasswordResetError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use bitwarden_crypto::AsymmetricPublicCryptoKey;

    let public_key = AsymmetricPublicCryptoKey::from_der(&STANDARD.decode(public_key)?)?;
    let enc = client.internal.get_encryption_settings()?;
    let key = enc.get_key(&None)?;

    Ok(AsymmetricEncString::encrypt_rsa2048_oaep_sha1(
        &key.to_vec(),
        &public_key,
    )?)
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeriveKeyConnectorRequest {
    /// Encrypted user key, used to validate the master key
    pub user_key_encrypted: EncString,

    pub password: String,
    pub kdf: Kdf,
    pub email: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DeriveKeyConnectorError {
    #[error(transparent)]
    WrongPassword(#[from] WrongPasswordError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Derive the master key for migrating to the key connector
pub(super) fn derive_key_connector(
    request: DeriveKeyConnectorRequest,
) -> Result<String, DeriveKeyConnectorError> {
    let master_key = MasterKey::derive(&request.password, &request.email, &request.kdf)?;
    master_key
        .decrypt_user_key(request.user_key_encrypted)
        .map_err(|_| WrongPasswordError)?;

    Ok(master_key.to_base64())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct MakeKeyPairResponse {
    /// The user's public key
    user_public_key: String,
    /// User's private key, encrypted with the user key
    user_key_encrypted_private_key: EncString,
}

pub fn make_key_pair(user_key: String) -> Result<MakeKeyPairResponse, CryptoError> {
    let user_key = UserKey::new(SymmetricCryptoKey::try_from(user_key)?);

    let key_pair = user_key.make_key_pair()?;

    Ok(MakeKeyPairResponse {
        user_public_key: key_pair.public,
        user_key_encrypted_private_key: key_pair.private,
    })
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct VerifyAsymmetricKeysRequest {
    /// The user's user key
    user_key: String,
    /// The user's public key
    user_public_key: String,
    /// User's private key, encrypted with the user key
    user_key_encrypted_private_key: EncString,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct VerifyAsymmetricKeysResponse {
    /// Whether the user's private key was decryptable by the user key.
    private_key_decryptable: bool,
    /// Whether the user's private key was a valid RSA key and matched the public key provided.
    valid_private_key: bool,
}

pub fn verify_asymmetric_keys(
    request: VerifyAsymmetricKeysRequest,
) -> Result<VerifyAsymmetricKeysResponse, CryptoError> {
    #[derive(Debug, thiserror::Error)]
    enum VerifyError {
        #[error("Failed to decrypt private key: {0:?}")]
        DecryptFailed(bitwarden_crypto::CryptoError),
        #[error("Failed to parse decrypted private key: {0:?}")]
        ParseFailed(bitwarden_crypto::CryptoError),
        #[error("Failed to derive a public key: {0:?}")]
        PublicFailed(bitwarden_crypto::CryptoError),
        #[error("Derived public key doesn't match")]
        KeyMismatch,
    }

    fn verify_inner(
        user_key: &SymmetricCryptoKey,
        request: &VerifyAsymmetricKeysRequest,
    ) -> Result<(), VerifyError> {
        let decrypted_private_key: Vec<u8> = request
            .user_key_encrypted_private_key
            .decrypt_with_key(user_key)
            .map_err(VerifyError::DecryptFailed)?;

        let private_key = AsymmetricCryptoKey::from_der(&decrypted_private_key)
            .map_err(VerifyError::ParseFailed)?;

        let derived_public_key_vec = private_key
            .to_public_der()
            .map_err(VerifyError::PublicFailed)?;

        let derived_public_key = STANDARD.encode(derived_public_key_vec);

        if derived_public_key != request.user_public_key {
            return Err(VerifyError::KeyMismatch);
        }
        Ok(())
    }

    let user_key = SymmetricCryptoKey::try_from(request.user_key.clone())?;

    Ok(match verify_inner(&user_key, &request) {
        Ok(_) => VerifyAsymmetricKeysResponse {
            private_key_decryptable: true,
            valid_private_key: true,
        },
        Err(e) => {
            log::debug!("User asymmetric keys verification: {}", e);

            VerifyAsymmetricKeysResponse {
                private_key_decryptable: !matches!(e, VerifyError::DecryptFailed(_)),
                valid_private_key: false,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_crypto::RsaKeyPair;

    use super::*;
    use crate::Client;

    #[tokio::test]
    async fn test_update_password() {
        let client = Client::new(None);

        let priv_key = "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw=";

        let kdf = Kdf::PBKDF2 {
            iterations: 100_000.try_into().unwrap(),
        };

        initialize_user_crypto(
            & client,
            InitUserCryptoRequest {
                kdf_params: kdf.clone(),
                email: "test@bitwarden.com".into(),
                private_key: priv_key.to_owned(),
                method: InitUserCryptoMethod::Password {
                    password: "asdfasdfasdf".into(),
                    user_key: "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc=".into(),
                },
            },
        )
        .await
        .unwrap();

        let new_password_response = update_password(&client, "123412341234".into()).unwrap();

        let client2 = Client::new(None);

        initialize_user_crypto(
            &client2,
            InitUserCryptoRequest {
                kdf_params: kdf.clone(),
                email: "test@bitwarden.com".into(),
                private_key: priv_key.to_owned(),
                method: InitUserCryptoMethod::Password {
                    password: "123412341234".into(),
                    user_key: new_password_response.new_key.to_string(),
                },
            },
        )
        .await
        .unwrap();

        let new_hash = client2
            .kdf()
            .hash_password(
                "test@bitwarden.com".into(),
                "123412341234".into(),
                kdf.clone(),
                bitwarden_crypto::HashPurpose::ServerAuthorization,
            )
            .await
            .unwrap();

        assert_eq!(new_hash, new_password_response.password_hash);

        assert_eq!(
            client
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64(),
            client2
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64()
        );
    }

    #[tokio::test]
    async fn test_initialize_user_crypto_pin() {
        let client = Client::new(None);

        let priv_key = "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw=";

        initialize_user_crypto(
            & client,
            InitUserCryptoRequest {
                kdf_params: Kdf::PBKDF2 {
                    iterations: 100_000.try_into().unwrap(),
                },
                email: "test@bitwarden.com".into(),
                private_key: priv_key.to_owned(),
                method: InitUserCryptoMethod::Password {
                    password: "asdfasdfasdf".into(),
                    user_key: "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc=".into(),
                },
            },
        )
        .await
        .unwrap();

        let pin_key = derive_pin_key(&client, "1234".into()).unwrap();

        // Verify we can unlock with the pin
        let client2 = Client::new(None);
        initialize_user_crypto(
            &client2,
            InitUserCryptoRequest {
                kdf_params: Kdf::PBKDF2 {
                    iterations: 100_000.try_into().unwrap(),
                },
                email: "test@bitwarden.com".into(),
                private_key: priv_key.to_owned(),
                method: InitUserCryptoMethod::Pin {
                    pin: "1234".into(),
                    pin_protected_user_key: pin_key.pin_protected_user_key,
                },
            },
        )
        .await
        .unwrap();

        assert_eq!(
            client
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64(),
            client2
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64()
        );

        // Verify we can derive the pin protected user key from the encrypted pin
        let pin_protected_user_key = derive_pin_user_key(&client, pin_key.encrypted_pin).unwrap();

        let client3 = Client::new(None);

        initialize_user_crypto(
            &client3,
            InitUserCryptoRequest {
                kdf_params: Kdf::PBKDF2 {
                    iterations: 100_000.try_into().unwrap(),
                },
                email: "test@bitwarden.com".into(),
                private_key: priv_key.to_owned(),
                method: InitUserCryptoMethod::Pin {
                    pin: "1234".into(),
                    pin_protected_user_key,
                },
            },
        )
        .await
        .unwrap();

        assert_eq!(
            client
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64(),
            client3
                .internal
                .get_encryption_settings()
                .unwrap()
                .get_key(&None)
                .unwrap()
                .to_base64()
        );
    }

    #[test]
    fn test_enroll_admin_password_reset() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use bitwarden_crypto::AsymmetricCryptoKey;

        let client = Client::new(None);

        let master_key = MasterKey::derive(
            "asdfasdfasdf",
            "test@bitwarden.com",
            &Kdf::PBKDF2 {
                iterations: NonZeroU32::new(600_000).unwrap(),
            },
        )
        .unwrap();

        let user_key = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=".parse().unwrap();
        let private_key ="2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=".parse().unwrap();
        client
            .internal
            .initialize_user_crypto_master_key(master_key, user_key, private_key)
            .unwrap();

        let public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsy7RFHcX3C8Q4/OMmhhbFReYWfB45W9PDTEA8tUZwZmtOiN2RErIS2M1c+K/4HoDJ/TjpbX1f2MZcr4nWvKFuqnZXyewFc+jmvKVewYi+NAu2++vqKq2kKcmMNhwoQDQdQIVy/Uqlp4Cpi2cIwO6ogq5nHNJGR3jm+CpyrafYlbz1bPvL3hbyoGDuG2tgADhyhXUdFuef2oF3wMvn1lAJAvJnPYpMiXUFmj1ejmbwtlxZDrHgUJvUcp7nYdwUKaFoi+sOttHn3u7eZPtNvxMjhSS/X/1xBIzP/mKNLdywH5LoRxniokUk+fV3PYUxJsiU3lV0Trc/tH46jqd8ZGjmwIDAQAB";

        let encrypted = enroll_admin_password_reset(&client, public_key.to_owned()).unwrap();

        let private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzLtEUdxfcLxDj84yaGFsVF5hZ8Hjlb08NMQDy1RnBma06I3ZESshLYzVz4r/gegMn9OOltfV/Yxlyvida8oW6qdlfJ7AVz6Oa8pV7BiL40C7b76+oqraQpyYw2HChANB1AhXL9SqWngKmLZwjA7qiCrmcc0kZHeOb4KnKtp9iVvPVs+8veFvKgYO4ba2AAOHKFdR0W55/agXfAy+fWUAkC8mc9ikyJdQWaPV6OZvC2XFkOseBQm9Rynudh3BQpoWiL6w620efe7t5k+02/EyOFJL9f/XEEjM/+Yo0t3LAfkuhHGeKiRST59Xc9hTEmyJTeVXROtz+0fjqOp3xkaObAgMBAAECggEACs4xhnO0HaZhh1/iH7zORMIRXKeyxP2LQiTR8xwN5JJ9wRWmGAR9VasS7EZFTDidIGVME2u/h4s5EqXnhxfO+0gGksVvgNXJ/qw87E8K2216g6ZNo6vSGA7H1GH2voWwejJ4/k/cJug6dz2S402rRAKh2Wong1arYHSkVlQp3diiMa5FHAOSE+Cy09O2ZsaF9IXQYUtlW6AVXFrBEPYH2kvkaPXchh8VETMijo6tbvoKLnUHe+wTaDMls7hy8exjtVyI59r3DNzjy1lNGaGb5QSnFMXR+eHhPZc844Wv02MxC15zKABADrl58gpJyjTl6XpDdHCYGsmGpVGH3X9TQQKBgQDz/9beFjzq59ve6rGwn+EtnQfSsyYT+jr7GN8lNEXb3YOFXBgPhfFIcHRh2R00Vm9w2ApfAx2cd8xm2I6HuvQ1Os7g26LWazvuWY0Qzb+KaCLQTEGH1RnTq6CCG+BTRq/a3J8M4t38GV5TWlzv8wr9U4dl6FR4efjb65HXs1GQ4QKBgQC7/uHfrOTEHrLeIeqEuSl0vWNqEotFKdKLV6xpOvNuxDGbgW4/r/zaxDqt0YBOXmRbQYSEhmO3oy9J6XfE1SUln0gbavZeW0HESCAmUIC88bDnspUwS9RxauqT5aF8ODKN/bNCWCnBM1xyonPOs1oT1nyparJVdQoG//Y7vkB3+wKBgBqLqPq8fKAp3XfhHLfUjREDVoiLyQa/YI9U42IOz9LdxKNLo6p8rgVthpvmnRDGnpUuS+KOWjhdqDVANjF6G3t3DG7WNl8Rh5Gk2H4NhFswfSkgQrjebFLlBy9gjQVCWXt8KSmjvPbiY6q52Aaa8IUjA0YJAregvXxfopxO+/7BAoGARicvEtDp7WWnSc1OPoj6N14VIxgYcI7SyrzE0d/1x3ffKzB5e7qomNpxKzvqrVP8DzG7ydh8jaKPmv1MfF8tpYRy3AhmN3/GYwCnPqT75YYrhcrWcVdax5gmQVqHkFtIQkRSCIftzPLlpMGKha/YBV8c1fvC4LD0NPh/Ynv0gtECgYEAyOZg95/kte0jpgUEgwuMrzkhY/AaUJULFuR5MkyvReEbtSBQwV5tx60+T95PHNiFooWWVXiLMsAgyI2IbkxVR1Pzdri3gWK5CTfqb7kLuaj/B7SGvBa2Sxo478KS5K8tBBBWkITqo+wLC0mn3uZi1dyMWO1zopTA+KtEGF2dtGQ=";
        let private_key =
            AsymmetricCryptoKey::from_der(&STANDARD.decode(private_key).unwrap()).unwrap();
        let decrypted: Vec<u8> = encrypted.decrypt_with_key(&private_key).unwrap();

        let enc = client.internal.get_encryption_settings().unwrap();
        let expected = enc.get_key(&None).unwrap();
        assert_eq!(&decrypted, &expected.to_vec());
    }

    #[test]
    fn test_derive_key_connector() {
        let request = DeriveKeyConnectorRequest {
            password: "asdfasdfasdf".to_string(),
            email: "test@bitwarden.com".to_string(),
            kdf: Kdf::PBKDF2 {
                iterations: NonZeroU32::new(600_000).unwrap(),
            },
            user_key_encrypted: "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=".parse().unwrap(),
        };

        let result = derive_key_connector(request).unwrap();

        assert_eq!(result, "ySXq1RVLKEaV1eoQE/ui9aFKIvXTl9PAXwp1MljfF50=");
    }

    fn setup_asymmetric_keys_test() -> (UserKey, RsaKeyPair) {
        let master_key = MasterKey::derive(
            "asdfasdfasdf",
            "test@bitwarden.com",
            &Kdf::PBKDF2 {
                iterations: NonZeroU32::new(600_000).unwrap(),
            },
        )
        .unwrap();
        let user_key = (master_key.make_user_key().unwrap()).0;
        let key_pair = user_key.make_key_pair().unwrap();

        (user_key, key_pair)
    }

    #[test]
    fn test_make_key_pair() {
        let (user_key, _) = setup_asymmetric_keys_test();

        let response = make_key_pair(user_key.0.to_base64()).unwrap();

        assert!(!response.user_public_key.is_empty());
        let encrypted_private_key = response.user_key_encrypted_private_key;
        let private_key: Vec<u8> = encrypted_private_key.decrypt_with_key(&user_key.0).unwrap();
        assert!(!private_key.is_empty());
    }

    #[test]
    fn test_verify_asymmetric_keys_success() {
        let (user_key, key_pair) = setup_asymmetric_keys_test();

        let request = VerifyAsymmetricKeysRequest {
            user_key: user_key.0.to_base64(),
            user_public_key: key_pair.public,
            user_key_encrypted_private_key: key_pair.private,
        };
        let response = verify_asymmetric_keys(request).unwrap();

        assert!(response.private_key_decryptable);
        assert!(response.valid_private_key);
    }

    #[test]
    fn test_verify_asymmetric_keys_decrypt_failed() {
        let (user_key, key_pair) = setup_asymmetric_keys_test();
        let undecryptable_private_key = "2.cqD39M4erPZ3tWaz2Fng9w==|+Bsp/xvM30oo+HThKN12qirK0A63EjMadcwethCX7kEgfL5nEXgAFsSgRBMpByc1djgpGDMXzUTLOE+FejXRsrEHH/ICZ7jPMgSR+lV64Mlvw3fgvDPQdJ6w3MCmjPueGQtrlPj1K78BkRomN3vQwwRBFUIJhLAnLshTOIFrSghoyG78na7McqVMMD0gmC0zmRaSs2YWu/46ES+2Rp8V5OC4qdeeoJM9MQfaOtmaqv7NRVDeDM3DwoyTJAOcon8eovMKE4jbFPUboiXjNQBkBgjvLhco3lVJnFcQuYgmjqrwuUQRsfAtZjxFXg/RQSH2D+SI5uRaTNQwkL4iJqIw7BIKtI0gxDz6eCVdq/+DLhpImgCV/aaIhF/jkpGqLCceFsYMbuqdULMM1VYKgV+IAuyC65R+wxOaKS+1IevvPnNp7tgKAvT5+shFg8piusj+rQ49daX2SmV2OImwdWMmmX93bcVV0xJ/WYB1yrqmyRUcTwyvX3RQF25P5okIIzFasRp8jXFZe8C6f93yzkn1TPQbp95zF4OsWjfPFVH4hzca07ACt2HjbAB75JakWbFA5MbCF8aOIwIfeLVhVlquQXCldOHCsl22U/f3HTGLB9OS8F83CDAy7qZqpKha9Im8RUhHoyf+lXrky0gyd6un7Ky8NSkVOGd8CEG7bvZfutxv/qtAjEM9/lV78fh8TQIy9GNgioMzplpuzPIJOgMaY/ZFZj6a8H9OMPneN5Je0H/DwHEglSyWy7CMgwcbQgXYGXc8rXTTxL71GUAFHzDr4bAJvf40YnjndoL9tf+oBw8vVNUccoD4cjyOT5w8h7M3Liaxk9/0O8JR98PKxxpv1Xw6XjFCSEHeG2y9FgDUASFR4ZwG1qQBiiLMnJ7e9kvxsdnmasBux9H0tOdhDhAM16Afk3NPPKA8eztJVHJBAfQiaNiUA4LIJ48d8EpUAe2Tvz0WW/gQThplUINDTpvPf+FojLwc5lFwNIPb4CVN1Ui8jOJI5nsOw4BSWJvLzJLxawHxX/sBuK96iXza+4aMH+FqYKt/twpTJtiVXo26sPtHe6xXtp7uO4b+bL9yYUcaAci69L0W8aNdu8iF0lVX6kFn2lOL8dBLRleGvixX9gYEVEsiI7BQBjxEBHW/YMr5F4M4smqCpleZIAxkse1r2fQ33BSOJVQKInt4zzgdKwrxDzuVR7RyiIUuNXHsprKtRHNJrSc4x5kWFUeivahed2hON+Ir/ZvrxYN6nJJPeYYH4uEm1Nn4osUzzfWILlqpmDPK1yYy365T38W8wT0cbdcJrI87ycS37HeB8bzpFJZSY/Dzv48Yy19mDZJHLJLCRqyxNeIlBPsVC8fvxQhzr+ZyS3Wi8Dsa2Sgjt/wd0xPULLCJlb37s+1aWgYYylr9QR1uhXheYfkXFED+saGWwY1jlYL5e2Oo9n3sviBYwJxIZ+RTKFgwlXV5S+Jx/MbDpgnVHP1KaoU6vvzdWYwMChdHV/6PhZVbeT2txq7Qt+zQN59IGrOWf6vlMkHxfUzMTD58CE+xAaz/D05ljHMesLj9hb3MSrymw0PcwoFGWUMIzIQE73pUVYNE7fVHa8HqUOdoxZ5dRZqXRVox1xd9siIPE3e6CuVQIMabTp1YLno=|Y38qtTuCwNLDqFnzJ3Cgbjm1SE15OnhDm9iAMABaQBA=".parse().unwrap();

        let request = VerifyAsymmetricKeysRequest {
            user_key: user_key.0.to_base64(),
            user_public_key: key_pair.public,
            user_key_encrypted_private_key: undecryptable_private_key,
        };
        let response = verify_asymmetric_keys(request).unwrap();

        assert!(!response.private_key_decryptable);
        assert!(!response.valid_private_key);
    }

    #[test]
    fn test_verify_asymmetric_keys_parse_failed() {
        let (user_key, key_pair) = setup_asymmetric_keys_test();

        let invalid_private_key = "bad_key"
            .to_string()
            .into_bytes()
            .encrypt_with_key(&user_key.0)
            .unwrap();

        let request = VerifyAsymmetricKeysRequest {
            user_key: user_key.0.to_base64(),
            user_public_key: key_pair.public,
            user_key_encrypted_private_key: invalid_private_key,
        };
        let response = verify_asymmetric_keys(request).unwrap();

        assert!(response.private_key_decryptable);
        assert!(!response.valid_private_key);
    }

    #[test]
    fn test_verify_asymmetric_keys_key_mismatch() {
        let (user_key, key_pair) = setup_asymmetric_keys_test();
        let new_key_pair = user_key.make_key_pair().unwrap();

        let request = VerifyAsymmetricKeysRequest {
            user_key: user_key.0.to_base64(),
            user_public_key: key_pair.public,
            user_key_encrypted_private_key: new_key_pair.private,
        };
        let response = verify_asymmetric_keys(request).unwrap();

        assert!(response.private_key_decryptable);
        assert!(!response.valid_private_key);
    }
}
