//! Client to manage the cryptographic machinery of a user account, including key-rotation
mod crypto;
mod data;
mod rotateable_keyset;
mod sync;
mod unlock;

use std::str::FromStr;

use bitwarden_api_api::models::RotateUserAccountKeysAndDataRequestModel;
use bitwarden_core::{
    Client, UserId,
    key_management::{
        MasterPasswordAuthenticationData, SignedSecurityState, SymmetricKeyId,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_crypto::{AsymmetricPublicCryptoKey, EncString, Kdf, SignedPublicKey};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, info_span, instrument, warn};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::key_rotation::{
    crypto::rotate_account_cryptographic_state,
    data::reencrypt_data,
    rotateable_keyset::KeysetUnlockData,
    unlock::{
        ReencryptUnlockInput, V1EmergencyAccessMembership, V1OrganizationMembership,
        reencrypt_unlock,
    },
};

/// Client for managing the cryptographic machinery of a user account, including key-rotation.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct UserCryptoManagementClient {
    pub(crate) client: Client,
}

impl UserCryptoManagementClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum MasterkeyUnlockMethod {
    Password {
        old_password: String,
        password: String,
        hint: Option<String>,
    },
    KeyConnector,
    None,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RotateUserKeysRequest {
    pub old_password: String,
    pub password: String,
    pub hint: Option<String>,
    pub trusted_emergency_access_public_keys: Vec<AsymmetricPublicCryptoKey>,
    pub trusted_organization_public_keys: Vec<AsymmetricPublicCryptoKey>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Rotates the user's encryption keys. The user must have a master-password.
    pub async fn rotate_user_keys_with_password_change(
        &self,
        request: RotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;

        post_rotate_user_keys(
            self,
            api_client,
            request.trusted_organization_public_keys,
            request.trusted_emergency_access_public_keys,
            MasterkeyUnlockMethod::Password {
                old_password: request.old_password,
                password: request.password,
                hint: request.hint,
            },
        )
        .await
    }
}

#[derive(Debug)]
enum SyncError {
    NetworkError,
    DataError,
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum RotateUserKeysError {
    #[error("API error during key rotation")]
    ApiError,
    #[error("Cryptographic error during key rotation")]
    CryptoError,
    #[error("Invalid public key provided during key rotation")]
    InvalidPublicKey,
    #[error("Untrusted key encountered during key rotation")]
    UntrustedKeyError,
}

struct UntrustedKeyError;

fn filter_trusted_organization(
    org: &[V1OrganizationMembership],
    trusted_orgs: &[AsymmetricPublicCryptoKey],
) -> Result<Vec<V1OrganizationMembership>, UntrustedKeyError> {
    org.iter()
        .map(|o| {
            let is_trusted = trusted_orgs.iter().any(|tk| tk == &o.public_key);
            if !is_trusted {
                warn!(
                    "Filtering out untrusted organization with id={}",
                    o.organization_id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(o.clone())
            }
        })
        .collect::<Result<Vec<V1OrganizationMembership>, UntrustedKeyError>>()
}

fn filter_trusted_emergency_access(
    ea: &[V1EmergencyAccessMembership],
    trusted_eas: &[AsymmetricPublicCryptoKey],
) -> Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError> {
    ea.iter()
        .map(|e| {
            let is_trusted = trusted_eas.iter().any(|tk| tk == &e.public_key);
            if !is_trusted {
                warn!(
                    "Filtering out untrusted emergency access membership with id={}",
                    e.id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(e.to_owned())
            }
        })
        .collect::<Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError>>()
}

async fn post_rotate_user_keys(
    registration_client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,

    trusted_organization_public_keys: Vec<AsymmetricPublicCryptoKey>,
    trusted_emergency_access_public_keys: Vec<AsymmetricPublicCryptoKey>,

    master_key_unlock_method: MasterkeyUnlockMethod,
) -> Result<(), RotateUserKeysError> {
    let _span = info_span!("rotate_user_keys").entered();
    let sync = sync::sync_current_account_data(api_client)
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;

    let key_store = registration_client.client.internal.get_key_store();
    // Create a separate scope so that the mutable context is not held across the await point
    let request = {
        let mut ctx = key_store.context_mut();

        // Filter organization memberships and emergency access memberships to only include trusted
        // keys
        let v1_organization_memberships = filter_trusted_organization(
            sync.organization_memberships.as_slice(),
            &trusted_organization_public_keys,
        )
        .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;
        let v1_emergency_access_memberships = filter_trusted_emergency_access(
            sync.emergency_access_memberships.as_slice(),
            &trusted_emergency_access_public_keys,
        )
        .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;

        info!(
            "Existing user cryptographic version {:?}",
            sync.wrapped_account_cryptographic_state
        );
        let current_user_key_id = SymmetricKeyId::User;

        debug!("Generating new xchacha20-poly1305 user key for key rotation");
        let new_user_key_id =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

        info!("Rotating account cryptographic state for user key rotation");
        let account_keys_model = rotate_account_cryptographic_state(
            &sync.wrapped_account_cryptographic_state,
            &current_user_key_id,
            &new_user_key_id,
            UserId::new(sync.user_id),
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account data for user key rotation");
        let account_data_model = reencrypt_data(
            sync.folders,
            sync.ciphers,
            sync.sends,
            &mut ctx,
            current_user_key_id,
            new_user_key_id,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account unlock data for user key rotation");
        let unlock_data_model = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method: match master_key_unlock_method {
                    MasterkeyUnlockMethod::Password {
                        old_password: _,
                        ref password,
                        ref hint,
                    } => {
                        let (kdf, salt) = sync
                            .kdf_and_salt
                            .clone()
                            .ok_or(RotateUserKeysError::ApiError)?;
                        unlock::MasterkeyUnlockMethod::Password {
                            password: password.to_owned(),
                            hint: hint.to_owned(),
                            kdf,
                            salt,
                        }
                    }
                    MasterkeyUnlockMethod::KeyConnector => {
                        unlock::MasterkeyUnlockMethod::KeyConnector
                    }
                    MasterkeyUnlockMethod::None => unlock::MasterkeyUnlockMethod::None,
                },
                trusted_devices: sync.trusted_devices,
                webauthn_credentials: sync.passkeys,
                trusted_organization_keys: v1_organization_memberships,
                trusted_emergency_access_keys: v1_emergency_access_memberships,
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        let old_masterpassword_authentication_data = match master_key_unlock_method {
            MasterkeyUnlockMethod::Password {
                old_password,
                password: _,
                hint: _,
            } => {
                let (kdf, salt) = sync
                    .kdf_and_salt
                    .clone()
                    .ok_or(RotateUserKeysError::ApiError)?;
                let authentication_data =
                    MasterPasswordAuthenticationData::derive(&old_password, &kdf, &salt)
                        .map_err(|_| RotateUserKeysError::CryptoError)?;
                Some(authentication_data)
            }
            MasterkeyUnlockMethod::KeyConnector => {
                tracing::error!("Key-connector based key rotation is not yet implemented");
                None
            }
            MasterkeyUnlockMethod::None => {
                tracing::error!(
                    "Key-rotation without master-key based unlock is not supported yet"
                );
                None
            }
        }
        .expect("Master password authentication data is required for password-based key rotation");
        RotateUserAccountKeysAndDataRequestModel {
            old_master_key_authentication_hash: Some(
                old_masterpassword_authentication_data
                    .master_password_authentication_hash
                    .to_string(),
            ),
            account_keys: Box::new(account_keys_model),
            account_data: Box::new(account_data_model),
            account_unlock_data: Box::new(unlock_data_model),
        }
    };

    info!("Posting rotated user account keys and data to server");
    registration_client
        .client
        .internal
        .get_api_configurations()
        .await
        .api_client
        .accounts_key_management_api()
        .rotate_user_account_keys(Some(request))
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

/// Extension trait to add the user-crypto-management client to the main Bitwarden SDK client.
pub trait UserCryptoManagementClientExt {
    /// Get the user-crypto-management client.
    fn user_crypto_management(&self) -> UserCryptoManagementClient;
}

impl UserCryptoManagementClientExt for Client {
    fn user_crypto_management(&self) -> UserCryptoManagementClient {
        UserCryptoManagementClient::new(self.clone())
    }
}

fn from_kdf(
    kdf: &bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel,
) -> Result<Kdf, ()> {
    Ok(match kdf.kdf_type {
        bitwarden_api_api::models::KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().map_err(|_| ())?)
                .ok_or(())?,
        },
        bitwarden_api_api::models::KdfType::Argon2id => {
            let memory = kdf.memory.ok_or(())?;
            let parallelism = kdf.parallelism.ok_or(())?;
            Kdf::Argon2id {
                iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().map_err(|_| ())?)
                    .ok_or(())?,
                memory: std::num::NonZeroU32::new(memory.try_into().map_err(|_| ())?).ok_or(())?,
                parallelism: std::num::NonZeroU32::new(parallelism.try_into().map_err(|_| ())?)
                    .ok_or(())?,
            }
        }
    })
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
enum PrivateKeysParsingError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid format in private keys response")]
    InvalidFormat,
}

#[instrument(skip(private_keys_response), err)]
fn from_private_keys_response(
    private_keys_response: &bitwarden_api_api::models::PrivateKeysResponseModel,
) -> Result<WrappedAccountCryptographicState, PrivateKeysParsingError> {
    let is_v2 = private_keys_response.signature_key_pair.is_some();
    if is_v2 {
        let private_key = private_keys_response
            .public_key_encryption_key_pair
            .wrapped_private_key
            .as_ref()
            .map(|pk| EncString::from_str(pk).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "private_key".to_string(),
            ))??;
        let signing_key = private_keys_response
            .signature_key_pair
            .as_ref()
            .and_then(|skp| skp.wrapped_signing_key.as_ref())
            .map(|s| EncString::from_str(s).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "signing_key".to_string(),
            ))??;
        let signed_public_key = private_keys_response
            .public_key_encryption_key_pair
            .signed_public_key
            .as_ref()
            .map(|spk| {
                SignedPublicKey::from_str(spk).map_err(|_| PrivateKeysParsingError::InvalidFormat)
            })
            .ok_or(PrivateKeysParsingError::MissingField(
                "signed_public_key".to_string(),
            ))??;
        let security_state = private_keys_response
            .security_state
            .as_ref()
            .map(|ss| {
                SignedSecurityState::from_str(&ss.security_state.clone().unwrap_or_default())
                    .map_err(|_| PrivateKeysParsingError::InvalidFormat)
            })
            .ok_or(PrivateKeysParsingError::MissingField(
                "security_state".to_string(),
            ))??;
        Ok(WrappedAccountCryptographicState::V2 {
            private_key,
            signed_public_key: Some(signed_public_key),
            signing_key,
            security_state,
        })
    } else {
        // V1: Private key, security state
        let private_key = private_keys_response
            .public_key_encryption_key_pair
            .wrapped_private_key
            .as_ref()
            .map(|pk| EncString::from_str(pk).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "private_key".to_string(),
            ))??;
        Ok(WrappedAccountCryptographicState::V1 { private_key })
    }
}
