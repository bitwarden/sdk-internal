use bitwarden_api_identity::{
    apis::accounts_api::accounts_register_post,
    models::{KeysRequestModel, RegisterRequestModel},
};
use bitwarden_crypto::{
    default_pbkdf2_iterations, CryptoError, EncString, HashPurpose, Kdf, MasterKey, RsaKeyPair,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiError, Client};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterRequest {
    pub email: String,
    pub name: Option<String>,
    pub password: String,
    pub password_hint: Option<String>,
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum RegisterError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Half baked implementation of user registration
pub(super) async fn register(client: &Client, req: &RegisterRequest) -> Result<(), RegisterError> {
    let config = client.internal.get_api_configurations().await;

    let kdf = Kdf::default();

    let keys = make_register_keys(req.email.to_owned(), req.password.to_owned(), kdf)?;

    accounts_register_post(
        &config.identity,
        Some(RegisterRequestModel {
            name: req.name.to_owned(),
            email: req.email.to_owned(),
            master_password_hash: keys.master_password_hash,
            master_password_hint: req.password_hint.to_owned(),
            captcha_response: None, // TODO: Add
            key: Some(keys.encrypted_user_key.to_string()),
            keys: Some(Box::new(KeysRequestModel {
                public_key: keys.keys.public,
                encrypted_private_key: keys.keys.private.to_string(),
            })),
            token: None,
            organization_user_id: None,
            kdf: Some(bitwarden_api_identity::models::KdfType::PBKDF2_SHA256),
            kdf_iterations: Some(default_pbkdf2_iterations().get() as i32),
            kdf_memory: None,
            kdf_parallelism: None,
            reference_data: None, // TODO: Add
        }),
    )
    .await
    .map_err(ApiError::from)?;

    Ok(())
}

pub(super) fn make_register_keys(
    email: String,
    password: String,
    kdf: Kdf,
) -> Result<RegisterKeyResponse, CryptoError> {
    let master_key = MasterKey::derive(&password, &email, &kdf)?;
    let master_password_hash =
        master_key.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization)?;
    let (user_key, encrypted_user_key) = master_key.make_user_key()?;
    let keys = user_key.make_key_pair()?;

    Ok(RegisterKeyResponse {
        master_password_hash,
        encrypted_user_key,
        keys,
    })
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RegisterKeyResponse {
    pub master_password_hash: String,
    pub encrypted_user_key: EncString,
    pub keys: RsaKeyPair,
}
