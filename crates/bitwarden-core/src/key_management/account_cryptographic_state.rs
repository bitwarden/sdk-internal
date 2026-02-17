//! User account cryptographic state
//!
//! This module contains initialization and unwrapping of the user account cryptographic state.
//! The user account cryptographic state contains keys and cryptographic objects unlocked by
//! the user-key, or protected by keys unlocked by the user-key.
//!
//! V1 users have only a private key protected by an AES256-CBC-HMAC user key.
//! V2 users have a private key, a signing key, a signed public key and a signed security state,
//! all protected by a Cose serialized AEAD key, currently XChaCha20-Poly1305.

use std::sync::RwLock;

use bitwarden_api_api::models::{
    AccountKeysRequestModel, PrivateKeysResponseModel, SecurityStateModel,
};
use bitwarden_crypto::{
    CoseSerializable, CryptoError, EncString, KeyStore, KeyStoreContext,
    PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SignedPublicKey, SymmetricKeyAlgorithm,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, instrument};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    MissingFieldError, UserId, require,
    key_management::{
        KeyIds, PrivateKeyId, SecurityState, SignedSecurityState, SigningKeyId, SymmetricKeyId,
    },
};

/// Errors that can occur during initialization of the account cryptographic state.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum AccountCryptographyInitializationError {
    /// The encryption algorithm from the user key does not match one of the encrypted items.
    /// This would mean that the user's account is corrupt.
    #[error("The encryption type of the user key does not match the account cryptographic state")]
    WrongUserKeyType,
    /// The provide user-key is incorrect or out-of-date. This may happen when a use-key changed
    /// and a local unlock-method is not yet updated.
    #[error("Wrong user key")]
    WrongUserKey,
    /// The decrypted data is corrupt.
    #[error("Decryption succeeded but produced corrupt data")]
    CorruptData,
    /// The decrypted data is corrupt.
    #[error("Signature or mac verification failed, the data may have been tampered with")]
    TamperedData,
    /// The key store is already initialized with account keys. Currently, updating keys is not a
    /// supported operation
    #[error("Key store is already initialized")]
    KeyStoreAlreadyInitialized,
    /// A generic cryptographic error occurred.
    #[error("A generic cryptographic error occurred: {0}")]
    GenericCrypto(CryptoError),
}

impl From<CryptoError> for AccountCryptographyInitializationError {
    fn from(err: CryptoError) -> Self {
        AccountCryptographyInitializationError::GenericCrypto(err)
    }
}

/// Errors that can occur during rotation of the account cryptographic state.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum RotateCryptographyStateError {
    /// The key is missing from the key store
    #[error("The provided key is missing from the key store")]
    KeyMissing,
    /// The provided data was invalid
    #[error("The provided data was invalid")]
    InvalidData,
}

/// Errors that can occur when parsing a `PrivateKeysResponseModel` into a
/// `WrappedAccountCryptographicState`.
#[derive(Debug, Error)]
pub enum AccountKeysResponseParseError {
    /// A required field was missing from the API response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A field value could not be parsed into the expected type.
    #[error("Malformed field value in API response")]
    MalformedField,
    /// The encryption type of the private key does not match the presence/absence of V2 fields.
    #[error("Inconsistent account cryptographic state in API response")]
    InconsistentState,
}

/// Any keys / cryptographic protection "downstream" from the account symmetric key (user key).
/// Private keys are protected by the user key.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(clippy::large_enum_variant)]
pub enum WrappedAccountCryptographicState {
    /// A V1 user has only a private key.
    V1 {
        /// The user's encryption private key, wrapped by the user key.
        private_key: EncString,
    },
    /// A V2 user has a private key, a signing key, a signed public key and a signed security state.
    /// The SignedPublicKey ensures that others can verify the public key is claimed by an identity
    /// they want to share data to. The signed security state protects against cryptographic
    /// downgrades.
    V2 {
        /// The user's encryption private key, wrapped by the user key.
        private_key: EncString,
        /// The user's public-key for the private key, signed by the user's signing key.
        /// Note: This is optional for backwards compatibility. After a few releases, this will be
        /// made non-optional once all clients store the response on sync.
        signed_public_key: Option<SignedPublicKey>,
        /// The user's signing key, wrapped by the user key.
        signing_key: EncString,
        /// The user's signed security state.
        security_state: SignedSecurityState,
    },
}

impl std::fmt::Debug for WrappedAccountCryptographicState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrappedAccountCryptographicState::V1 { .. } => f
                .debug_struct("WrappedAccountCryptographicState::V1")
                .finish(),
            WrappedAccountCryptographicState::V2 { .. } => f
                .debug_struct("WrappedAccountCryptographicState::V2")
                .finish(),
        }
    }
}

impl TryFrom<&PrivateKeysResponseModel> for WrappedAccountCryptographicState {
    type Error = AccountKeysResponseParseError;

    fn try_from(response: &PrivateKeysResponseModel) -> Result<Self, Self::Error> {
        let private_key: EncString =
            require!(&response.public_key_encryption_key_pair.wrapped_private_key)
                .parse()
                .map_err(|_| AccountKeysResponseParseError::MalformedField)?;

        let is_v2_encryption = matches!(private_key, EncString::Cose_Encrypt0_B64 { .. });

        if is_v2_encryption {
            let signature_key_pair = response
                .signature_key_pair
                .as_ref()
                .ok_or(AccountKeysResponseParseError::InconsistentState)?;

            let signing_key: EncString = require!(&signature_key_pair.wrapped_signing_key)
                .parse()
                .map_err(|_| AccountKeysResponseParseError::MalformedField)?;

            let signed_public_key: Option<SignedPublicKey> = response
                .public_key_encryption_key_pair
                .signed_public_key
                .as_ref()
                .map(|spk| spk.parse())
                .transpose()
                .map_err(|_| AccountKeysResponseParseError::MalformedField)?;

            let security_state_model = response
                .security_state
                .as_ref()
                .ok_or(AccountKeysResponseParseError::InconsistentState)?;
            let security_state: SignedSecurityState =
                require!(&security_state_model.security_state)
                    .parse()
                    .map_err(|_| AccountKeysResponseParseError::MalformedField)?;

            Ok(WrappedAccountCryptographicState::V2 {
                private_key,
                signed_public_key,
                signing_key,
                security_state,
            })
        } else {
            if response.signature_key_pair.is_some() || response.security_state.is_some() {
                return Err(AccountKeysResponseParseError::InconsistentState);
            }

            Ok(WrappedAccountCryptographicState::V1 { private_key })
        }
    }
}

impl WrappedAccountCryptographicState {
    /// Converts to a AccountKeysRequestModel in order to make API requests. Since the
    /// [WrappedAccountCryptographicState] is encrypted, the key store needs to contain the
    /// user key required to unlock this state.
    #[instrument(skip_all, err)]
    pub fn to_request_model(
        &self,
        user_key: &SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<AccountKeysRequestModel, AccountCryptographyInitializationError> {
        let private_key = match self {
            WrappedAccountCryptographicState::V1 { private_key }
            | WrappedAccountCryptographicState::V2 { private_key, .. } => private_key.clone(),
        };
        let private_key_tmp_id = ctx.unwrap_private_key(*user_key, &private_key)?;
        let public_key = ctx.get_public_key(private_key_tmp_id)?;

        let signature_keypair = match self {
            WrappedAccountCryptographicState::V1 { .. } => None,
            WrappedAccountCryptographicState::V2 { signing_key, .. } => {
                let signing_key_tmp_id = ctx.unwrap_signing_key(*user_key, signing_key)?;
                let verifying_key = ctx.get_verifying_key(signing_key_tmp_id)?;
                Some((signing_key.clone(), verifying_key))
            }
        };

        Ok(AccountKeysRequestModel {
            // Note: This property is deprecated and should be removed after a transition period.
            user_key_encrypted_account_private_key: Some(private_key.to_string()),
            // Note: This property is deprecated and should be removed after a transition period.
            account_public_key: Some(B64::from(public_key.to_der()?).to_string()),
            signature_key_pair: signature_keypair
                .as_ref()
                .map(|(signing_key, verifying_key)| {
                    Box::new(bitwarden_api_api::models::SignatureKeyPairRequestModel {
                        wrapped_signing_key: Some(signing_key.to_string()),
                        verifying_key: Some(B64::from(verifying_key.to_cose()).to_string()),
                        signature_algorithm: Some(match verifying_key.algorithm() {
                            SignatureAlgorithm::Ed25519 => "ed25519".to_string(),
                        }),
                    })
                }),
            public_key_encryption_key_pair: Some(Box::new(
                bitwarden_api_api::models::PublicKeyEncryptionKeyPairRequestModel {
                    wrapped_private_key: match self {
                        WrappedAccountCryptographicState::V1 { private_key }
                        | WrappedAccountCryptographicState::V2 { private_key, .. } => {
                            Some(private_key.to_string())
                        }
                    },
                    public_key: Some(B64::from(public_key.to_der()?).to_string()),
                    signed_public_key: match self.signed_public_key() {
                        Ok(Some(spk)) => Some(spk.clone().into()),
                        _ => None,
                    },
                },
            )),
            security_state: match (self, signature_keypair.as_ref()) {
                (_, None) | (WrappedAccountCryptographicState::V1 { .. }, Some(_)) => None,
                (
                    WrappedAccountCryptographicState::V2 { security_state, .. },
                    Some((_, verifying_key)),
                ) => {
                    // Convert the verified state's version to i32 for the API model
                    Some(Box::new(SecurityStateModel {
                        security_state: Some(security_state.into()),
                        security_version: security_state
                            .to_owned()
                            .verify_and_unwrap(verifying_key)
                            .map_err(|_| AccountCryptographyInitializationError::TamperedData)?
                            .version() as i32,
                    }))
                }
            },
        })
    }

    /// Creates a new V2 account cryptographic state with fresh keys. This does not change the user
    /// state, but does set some keys to the local context.
    pub fn make(
        ctx: &mut KeyStoreContext<KeyIds>,
        user_id: UserId,
    ) -> Result<(SymmetricKeyId, Self), AccountCryptographyInitializationError> {
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signing_key = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let signed_public_key = ctx.make_signed_public_key(private_key, signing_key)?;

        let security_state = SecurityState::initialize_for_user(user_id);
        let signed_security_state = security_state.sign(signing_key, ctx)?;

        Ok((
            user_key,
            WrappedAccountCryptographicState::V2 {
                private_key: ctx.wrap_private_key(user_key, private_key)?,
                signed_public_key: Some(signed_public_key),
                signing_key: ctx.wrap_signing_key(user_key, signing_key)?,
                security_state: signed_security_state,
            },
        ))
    }

    #[cfg(test)]
    fn make_v1(
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<(SymmetricKeyId, Self), AccountCryptographyInitializationError> {
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        Ok((
            user_key,
            WrappedAccountCryptographicState::V1 {
                private_key: ctx.wrap_private_key(user_key, private_key)?,
            },
        ))
    }

    /// Re-wraps the account cryptographic state with a new user key. If the cryptographic state is
    /// a V1 state, it gets upgraded to a V2 state
    #[instrument(skip(self, ctx), err)]
    pub fn rotate(
        &self,
        current_user_key: &SymmetricKeyId,
        new_user_key: &SymmetricKeyId,
        user_id: UserId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, RotateCryptographyStateError> {
        match self {
            WrappedAccountCryptographicState::V1 { private_key } => {
                // To upgrade a V1 state to a V2 state,
                // 1. The private key is re-encrypted
                // 2. The signing key is generated
                // 3. The public key is signed and
                // 4. The security state is initialized and signed.

                // 1. Re-encrypt private key
                let private_key_id = ctx
                    .unwrap_private_key(*current_user_key, private_key)
                    .map_err(|_| RotateCryptographyStateError::InvalidData)?;
                let new_private_key = ctx
                    .wrap_private_key(*new_user_key, private_key_id)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                // 2. The signing key is generated
                let signing_key_id = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
                let new_signing_key = ctx
                    .wrap_signing_key(*new_user_key, signing_key_id)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                // 3. The public key is signed and
                let signed_public_key = ctx
                    .make_signed_public_key(private_key_id, signing_key_id)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                // 4. The security state is initialized and signed.
                let security_state = SecurityState::initialize_for_user(user_id);
                let signed_security_state = security_state
                    .sign(signing_key_id, ctx)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                Ok(WrappedAccountCryptographicState::V2 {
                    private_key: new_private_key,
                    signed_public_key: Some(signed_public_key),
                    signing_key: new_signing_key,
                    security_state: signed_security_state,
                })
            }
            WrappedAccountCryptographicState::V2 {
                private_key,
                signed_public_key,
                signing_key,
                security_state,
            } => {
                // To rotate a V2 state, the private and signing keys are re-encrypted with the new
                // user key.
                // 1. Re-encrypt private key
                let private_key_id = ctx
                    .unwrap_private_key(*current_user_key, private_key)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;
                let new_private_key = ctx
                    .wrap_private_key(*new_user_key, private_key_id)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                // 2. Re-encrypt signing key
                let signing_key_id = ctx
                    .unwrap_signing_key(*current_user_key, signing_key)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;
                let new_signing_key = ctx
                    .wrap_signing_key(*new_user_key, signing_key_id)
                    .map_err(|_| RotateCryptographyStateError::KeyMissing)?;

                Ok(WrappedAccountCryptographicState::V2 {
                    private_key: new_private_key,
                    signed_public_key: signed_public_key.clone(),
                    signing_key: new_signing_key,
                    security_state: security_state.clone(),
                })
            }
        }
    }

    /// Set the decrypted account cryptographic state to the context's non-local storage.
    /// This needs a mutable context passed in that already has a user_key set to a local key slot,
    /// for which the id is passed in as `user_key`. Note, that this function drops the context
    /// and clears the existing local state, after persisting it.
    pub(crate) fn set_to_context(
        &self,
        security_state_rwlock: &RwLock<Option<SecurityState>>,
        user_key: SymmetricKeyId,
        store: &KeyStore<KeyIds>,
        mut ctx: KeyStoreContext<KeyIds>,
    ) -> Result<(), AccountCryptographyInitializationError> {
        if ctx.has_symmetric_key(SymmetricKeyId::User)
            || ctx.has_private_key(PrivateKeyId::UserPrivateKey)
            || ctx.has_signing_key(SigningKeyId::UserSigningKey)
        {
            return Err(AccountCryptographyInitializationError::KeyStoreAlreadyInitialized);
        }

        match self {
            WrappedAccountCryptographicState::V1 { private_key } => {
                info!("Initializing V1 account cryptographic state");
                if ctx.get_symmetric_key_algorithm(user_key)?
                    != SymmetricKeyAlgorithm::Aes256CbcHmac
                {
                    return Err(AccountCryptographyInitializationError::WrongUserKeyType);
                }

                // Some users have unreadable V1 private keys. In this case, we set no keys to
                // state.
                if let Ok(private_key_id) = ctx.unwrap_private_key(user_key, private_key) {
                    ctx.persist_private_key(private_key_id, PrivateKeyId::UserPrivateKey)?;
                } else {
                    tracing::warn!(
                        "V1 private key could not be unwrapped, skipping setting private key"
                    );
                }

                ctx.persist_symmetric_key(user_key, SymmetricKeyId::User)?;
            }
            WrappedAccountCryptographicState::V2 {
                private_key,
                signed_public_key,
                signing_key,
                security_state,
            } => {
                info!("Initializing V2 account cryptographic state");
                if ctx.get_symmetric_key_algorithm(user_key)?
                    != SymmetricKeyAlgorithm::XChaCha20Poly1305
                {
                    return Err(AccountCryptographyInitializationError::WrongUserKeyType);
                }

                let private_key_id = ctx
                    .unwrap_private_key(user_key, private_key)
                    .map_err(|_| AccountCryptographyInitializationError::WrongUserKey)?;
                let signing_key_id = ctx
                    .unwrap_signing_key(user_key, signing_key)
                    .map_err(|_| AccountCryptographyInitializationError::WrongUserKey)?;

                if let Some(signed_public_key) = signed_public_key {
                    signed_public_key
                        .to_owned()
                        .verify_and_unwrap(&ctx.get_verifying_key(signing_key_id)?)
                        .map_err(|_| AccountCryptographyInitializationError::TamperedData)?;
                }

                let security_state: SecurityState = security_state
                    .to_owned()
                    .verify_and_unwrap(&ctx.get_verifying_key(signing_key_id)?)
                    .map_err(|_| AccountCryptographyInitializationError::TamperedData)?;
                ctx.persist_private_key(private_key_id, PrivateKeyId::UserPrivateKey)?;
                ctx.persist_signing_key(signing_key_id, SigningKeyId::UserSigningKey)?;
                ctx.persist_symmetric_key(user_key, SymmetricKeyId::User)?;
                // Not manually dropping ctx here would lead to a deadlock, since storing the state
                // needs to acquire a lock on the inner key store
                drop(ctx);
                store.set_security_state_version(security_state.version());
                *security_state_rwlock.write().expect("RwLock not poisoned") = Some(security_state);
            }
        }

        Ok(())
    }

    /// Retrieve the signed public key from the wrapped state, if present.
    fn signed_public_key(
        &self,
    ) -> Result<Option<&SignedPublicKey>, AccountCryptographyInitializationError> {
        match self {
            WrappedAccountCryptographicState::V1 { .. } => Ok(None),
            WrappedAccountCryptographicState::V2 {
                signed_public_key, ..
            } => Ok(signed_public_key.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::RwLock};

    use bitwarden_crypto::{KeyStore, PrimitiveEncryptable};

    use super::*;
    use crate::key_management::{PrivateKeyId, SigningKeyId, SymmetricKeyId};

    #[test]
    fn test_set_to_context_v1() {
        // Prepare a temporary store to create wrapped state using a known user key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();

        // Create a V1-style user key (Aes256CbcHmac) and add to temp context
        let user_key = temp_ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Make a private key and wrap it with the user key
        let private_key_id = temp_ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped_private = temp_ctx.wrap_private_key(user_key, private_key_id).unwrap();

        // Construct the V1 wrapped state
        let wrapped = WrappedAccountCryptographicState::V1 {
            private_key: wrapped_private,
        };
        #[allow(deprecated)]
        let user_key = temp_ctx
            .dangerous_get_symmetric_key(user_key)
            .unwrap()
            .to_owned();
        drop(temp_ctx);
        drop(temp_store);

        // Now attempt to set this wrapped state into a fresh store using the same user key
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.add_local_symmetric_key(user_key);
        let security_state = RwLock::new(None);

        // This should succeed and move keys into the expected global slots
        wrapped
            .set_to_context(&security_state, user_key, &store, ctx)
            .unwrap();
        let ctx = store.context();

        // Assert that the private key and user symmetric key were set in the store
        assert!(ctx.has_private_key(PrivateKeyId::UserPrivateKey));
        assert!(ctx.has_symmetric_key(SymmetricKeyId::User));
    }

    #[test]
    fn test_set_to_context_v2() {
        // Prepare a temporary store to create wrapped state using a known user key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();

        // Create a V2-style user key (XChaCha20Poly1305) and add to temp context
        let user_key = temp_ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Make keys
        let private_key_id = temp_ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signing_key_id = temp_ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let signed_public_key = temp_ctx
            .make_signed_public_key(private_key_id, signing_key_id)
            .unwrap();

        // Sign and wrap security state
        let user_id = UserId::new_v4();
        let security_state = SecurityState::initialize_for_user(user_id);
        let signed_security_state = security_state.sign(signing_key_id, &mut temp_ctx).unwrap();

        // Wrap the private and signing keys with the user key
        let wrapped_private = temp_ctx.wrap_private_key(user_key, private_key_id).unwrap();
        let wrapped_signing = temp_ctx.wrap_signing_key(user_key, signing_key_id).unwrap();

        let wrapped = WrappedAccountCryptographicState::V2 {
            private_key: wrapped_private,
            signed_public_key: Some(signed_public_key),
            signing_key: wrapped_signing,
            security_state: signed_security_state,
        };
        #[allow(deprecated)]
        let user_key = temp_ctx
            .dangerous_get_symmetric_key(user_key)
            .unwrap()
            .to_owned();
        drop(temp_ctx);
        drop(temp_store);

        // Now attempt to set this wrapped state into a fresh store using the same user key
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.add_local_symmetric_key(user_key);
        let security_state = RwLock::new(None);

        wrapped
            .set_to_context(&security_state, user_key, &store, ctx)
            .unwrap();

        assert!(store.context().has_symmetric_key(SymmetricKeyId::User));
        // Assert that the account keys and security state were set
        assert!(
            store
                .context()
                .has_private_key(PrivateKeyId::UserPrivateKey)
        );
        assert!(
            store
                .context()
                .has_signing_key(SigningKeyId::UserSigningKey)
        );
        // Ensure security state was recorded
        assert!(security_state.read().unwrap().is_some());
    }

    #[test]
    fn test_to_private_keys_request_model_v2() {
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();
        let user_id = UserId::new_v4();
        let (user_key, wrapped_account_cryptography_state) =
            WrappedAccountCryptographicState::make(&mut temp_ctx, user_id).unwrap();

        wrapped_account_cryptography_state
            .set_to_context(&RwLock::new(None), user_key, &temp_store, temp_ctx)
            .unwrap();

        let mut ctx = temp_store.context_mut();
        let model = wrapped_account_cryptography_state
            .to_request_model(&SymmetricKeyId::User, &mut ctx)
            .expect("to_private_keys_request_model should succeed");
        drop(ctx);

        let ctx = temp_store.context();

        let sig_pair = model
            .signature_key_pair
            .expect("signature_key_pair present");
        assert_eq!(
            sig_pair.verifying_key.unwrap(),
            B64::from(
                ctx.get_verifying_key(SigningKeyId::UserSigningKey)
                    .unwrap()
                    .to_cose()
            )
            .to_string()
        );

        let pk_pair = model.public_key_encryption_key_pair.unwrap();
        assert_eq!(
            pk_pair.public_key.unwrap(),
            B64::from(
                ctx.get_public_key(PrivateKeyId::UserPrivateKey)
                    .unwrap()
                    .to_der()
                    .unwrap()
            )
            .to_string()
        );

        let signed_security_state = model
            .security_state
            .clone()
            .expect("security_state present");
        let security_state =
            SignedSecurityState::from_str(signed_security_state.security_state.unwrap().as_str())
                .unwrap()
                .verify_and_unwrap(&ctx.get_verifying_key(SigningKeyId::UserSigningKey).unwrap())
                .expect("security state should verify");
        assert_eq!(
            security_state.version(),
            model.security_state.unwrap().security_version as u64
        );
    }

    #[test]
    fn test_set_to_context_v1_corrupt_private_key() {
        // Test that a V1 account with a corrupt private key (valid EncString but invalid key data)
        // can still initialize, but skips setting the private key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();

        let user_key = temp_ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let corrupt_private_key = "not a private key"
            .encrypt(&mut temp_ctx, user_key)
            .unwrap();

        // Construct the V1 wrapped state with corrupt private key
        let wrapped = WrappedAccountCryptographicState::V1 {
            private_key: corrupt_private_key,
        };

        #[expect(deprecated)]
        let user_key_material = temp_ctx
            .dangerous_get_symmetric_key(user_key)
            .unwrap()
            .to_owned();
        drop(temp_ctx);
        drop(temp_store);

        // Now attempt to set this wrapped state into a fresh store
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.add_local_symmetric_key(user_key_material);
        let security_state = RwLock::new(None);

        wrapped
            .set_to_context(&security_state, user_key, &store, ctx)
            .unwrap();

        let ctx = store.context();

        // The user symmetric key should be set
        assert!(ctx.has_symmetric_key(SymmetricKeyId::User));
        // But the private key should NOT be set (due to corruption)
        assert!(!ctx.has_private_key(PrivateKeyId::UserPrivateKey));
    }

    #[test]
    fn test_try_from_response_v2_roundtrip() {
        use bitwarden_api_api::models::{
            PublicKeyEncryptionKeyPairResponseModel, SecurityStateModel,
            SignatureKeyPairResponseModel,
        };

        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();
        let user_id = UserId::new_v4();
        let (user_key, wrapped_state) =
            WrappedAccountCryptographicState::make(&mut temp_ctx, user_id).unwrap();

        wrapped_state
            .set_to_context(&RwLock::new(None), user_key, &temp_store, temp_ctx)
            .unwrap();

        let mut ctx = temp_store.context_mut();
        let request_model = wrapped_state
            .to_request_model(&SymmetricKeyId::User, &mut ctx)
            .unwrap();
        drop(ctx);

        let pk_pair = request_model.public_key_encryption_key_pair.unwrap();
        let sig_pair = request_model.signature_key_pair.unwrap();
        let sec_state = request_model.security_state.unwrap();

        let response = PrivateKeysResponseModel {
            object: None,
            public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                object: None,
                wrapped_private_key: pk_pair.wrapped_private_key,
                public_key: pk_pair.public_key,
                signed_public_key: pk_pair.signed_public_key,
            }),
            signature_key_pair: Some(Box::new(SignatureKeyPairResponseModel {
                object: None,
                wrapped_signing_key: sig_pair.wrapped_signing_key,
                verifying_key: sig_pair.verifying_key,
            })),
            security_state: Some(Box::new(SecurityStateModel {
                security_state: sec_state.security_state,
                security_version: sec_state.security_version,
            })),
        };

        let parsed = WrappedAccountCryptographicState::try_from(&response)
            .expect("V2 response should parse successfully");

        match &parsed {
            WrappedAccountCryptographicState::V2 {
                private_key,
                signed_public_key,
                signing_key,
                ..
            } => {
                match &wrapped_state {
                    WrappedAccountCryptographicState::V2 {
                        private_key: orig_private_key,
                        signed_public_key: orig_signed_public_key,
                        signing_key: orig_signing_key,
                        ..
                    } => {
                        assert_eq!(private_key.to_string(), orig_private_key.to_string());
                        assert_eq!(signing_key.to_string(), orig_signing_key.to_string());
                        assert_eq!(
                            signed_public_key.as_ref().map(|k| String::from(k.clone())),
                            orig_signed_public_key
                                .as_ref()
                                .map(|k| String::from(k.clone())),
                        );
                    }
                    _ => panic!("Original state should be V2"),
                }
            }
            _ => panic!("Parsed state should be V2"),
        }
    }

    #[test]
    fn test_try_from_response_v1() {
        use bitwarden_api_api::models::PublicKeyEncryptionKeyPairResponseModel;

        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();
        let (_user_key, wrapped_state) =
            WrappedAccountCryptographicState::make_v1(&mut temp_ctx).unwrap();

        let wrapped_private_key = match &wrapped_state {
            WrappedAccountCryptographicState::V1 { private_key } => private_key.to_string(),
            _ => panic!("Expected V1"),
        };
        drop(temp_ctx);

        let response = PrivateKeysResponseModel {
            object: None,
            public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                object: None,
                wrapped_private_key: Some(wrapped_private_key.clone()),
                public_key: None,
                signed_public_key: None,
            }),
            signature_key_pair: None,
            security_state: None,
        };

        let parsed = WrappedAccountCryptographicState::try_from(&response)
            .expect("V1 response should parse successfully");

        match &parsed {
            WrappedAccountCryptographicState::V1 { private_key } => {
                assert_eq!(private_key.to_string(), wrapped_private_key);
            }
            _ => panic!("Parsed state should be V1"),
        }
    }

    #[test]
    fn test_try_from_response_missing_private_key() {
        use bitwarden_api_api::models::PublicKeyEncryptionKeyPairResponseModel;

        let response = PrivateKeysResponseModel {
            object: None,
            public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                object: None,
                wrapped_private_key: None,
                public_key: None,
                signed_public_key: None,
            }),
            signature_key_pair: None,
            security_state: None,
        };

        let result = WrappedAccountCryptographicState::try_from(&response);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                AccountKeysResponseParseError::MissingField(_)
            ),
            "Should return MissingField error"
        );
    }

    #[test]
    fn test_try_from_response_v2_encryption_missing_signature_key_pair() {
        use bitwarden_api_api::models::PublicKeyEncryptionKeyPairResponseModel;

        // Create a V2 state to get a COSE-encrypted private key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();
        let user_id = UserId::new_v4();
        let (user_key, wrapped_state) =
            WrappedAccountCryptographicState::make(&mut temp_ctx, user_id).unwrap();

        wrapped_state
            .set_to_context(&RwLock::new(None), user_key, &temp_store, temp_ctx)
            .unwrap();

        let mut ctx = temp_store.context_mut();
        let request_model = wrapped_state
            .to_request_model(&SymmetricKeyId::User, &mut ctx)
            .unwrap();
        drop(ctx);

        let pk_pair = request_model.public_key_encryption_key_pair.unwrap();

        // V2-encrypted private key but no signature_key_pair or security_state
        let response = PrivateKeysResponseModel {
            object: None,
            public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                object: None,
                wrapped_private_key: pk_pair.wrapped_private_key,
                public_key: pk_pair.public_key,
                signed_public_key: None,
            }),
            signature_key_pair: None,
            security_state: None,
        };

        let result = WrappedAccountCryptographicState::try_from(&response);
        assert!(matches!(
            result.unwrap_err(),
            AccountKeysResponseParseError::InconsistentState
        ));
    }

    #[test]
    fn test_try_from_response_v1_encryption_with_unexpected_v2_fields() {
        use bitwarden_api_api::models::{
            PublicKeyEncryptionKeyPairResponseModel, SignatureKeyPairResponseModel,
        };

        // Create a V1 state to get an AES-encrypted private key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();
        let (_user_key, wrapped_state) =
            WrappedAccountCryptographicState::make_v1(&mut temp_ctx).unwrap();

        let wrapped_private_key = match &wrapped_state {
            WrappedAccountCryptographicState::V1 { private_key } => private_key.to_string(),
            _ => panic!("Expected V1"),
        };
        drop(temp_ctx);

        // V1-encrypted private key but with a signature_key_pair present
        let response = PrivateKeysResponseModel {
            object: None,
            public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                object: None,
                wrapped_private_key: Some(wrapped_private_key),
                public_key: None,
                signed_public_key: None,
            }),
            signature_key_pair: Some(Box::new(SignatureKeyPairResponseModel {
                object: None,
                wrapped_signing_key: Some("bogus".to_string()),
                verifying_key: None,
            })),
            security_state: None,
        };

        let result = WrappedAccountCryptographicState::try_from(&response);
        assert!(matches!(
            result.unwrap_err(),
            AccountKeysResponseParseError::InconsistentState
        ));
    }

    #[test]
    fn test_rotate_v1_to_v2() {
        // Create a key store and context
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Create a V1-style user key and add to context
        let user_id = UserId::new_v4();
        let (old_user_key_id, wrapped_state) =
            WrappedAccountCryptographicState::make_v1(&mut ctx).unwrap();
        let new_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        #[allow(deprecated)]
        let new_user_key_owned = ctx
            .dangerous_get_symmetric_key(new_user_key_id)
            .unwrap()
            .to_owned();
        wrapped_state
            .set_to_context(&RwLock::new(None), old_user_key_id, &store, ctx)
            .unwrap();

        // The previous context got consumed, so we are creating a new one here. Setting the state
        // to context persisted the user-key and other keys
        let mut ctx = store.context_mut();
        let new_user_key_id = ctx.add_local_symmetric_key(new_user_key_owned.clone());

        // Rotate the state
        let rotated_state = wrapped_state
            .rotate(&SymmetricKeyId::User, &new_user_key_id, user_id, &mut ctx)
            .unwrap();

        // We need to ensure two things after a rotation from V1 to V2:
        // 1. The new state is valid and can be set to context
        // 2. The new state uses the same private and signing keys

        // 1. The new state is valid and can be set to context
        match rotated_state {
            WrappedAccountCryptographicState::V2 { .. } => {}
            _ => panic!("Expected V2 after rotation from V1"),
        }
        let store_2 = KeyStore::<KeyIds>::default();
        let mut ctx_2 = store_2.context_mut();
        let user_key_id = ctx_2.add_local_symmetric_key(new_user_key_owned.clone());
        rotated_state
            .set_to_context(&RwLock::new(None), user_key_id, &store_2, ctx_2)
            .unwrap();
        // The context was consumed, so we create a new one to inspect the keys
        let ctx_2 = store_2.context();

        // 2. The new state uses the same private and signing keys
        let public_key_before_rotation = ctx
            .get_public_key(PrivateKeyId::UserPrivateKey)
            .expect("Private key should be present in context before rotation");
        let public_key_after_rotation = ctx_2
            .get_public_key(PrivateKeyId::UserPrivateKey)
            .expect("Private key should be present in context after rotation");
        assert_eq!(
            public_key_before_rotation.to_der().unwrap(),
            public_key_after_rotation.to_der().unwrap(),
            "Private key should be preserved during rotation from V2 to V2"
        );
    }

    #[test]
    fn test_rotate_v2() {
        // Create a key store and context
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Create a V2-style user key and add to context
        let user_id = UserId::new_v4();
        let (old_user_key_id, wrapped_state) =
            WrappedAccountCryptographicState::make(&mut ctx, user_id).unwrap();
        let new_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        #[allow(deprecated)]
        let new_user_key_owned = ctx
            .dangerous_get_symmetric_key(new_user_key_id)
            .unwrap()
            .to_owned();
        wrapped_state
            .set_to_context(&RwLock::new(None), old_user_key_id, &store, ctx)
            .unwrap();

        // The previous context got consumed, so we are creating a new one here. Setting the state
        // to context persisted the user-key and other keys
        let mut ctx = store.context_mut();
        let new_user_key_id = ctx.add_local_symmetric_key(new_user_key_owned.clone());

        // Rotate the state
        let rotated_state = wrapped_state
            .rotate(&SymmetricKeyId::User, &new_user_key_id, user_id, &mut ctx)
            .unwrap();

        // We need to ensure two things after a rotation from V1 to V2:
        // 1. The new state is valid and can be set to context
        // 2. The new state uses the same private and signing keys

        // 1. The new state is valid and can be set to context
        match rotated_state {
            WrappedAccountCryptographicState::V2 { .. } => {}
            _ => panic!("Expected V2 after rotation from V2"),
        }
        let store_2 = KeyStore::<KeyIds>::default();
        let mut ctx_2 = store_2.context_mut();
        let user_key_id = ctx_2.add_local_symmetric_key(new_user_key_owned.clone());
        rotated_state
            .set_to_context(&RwLock::new(None), user_key_id, &store_2, ctx_2)
            .unwrap();
        // The context was consumed, so we create a new one to inspect the keys
        let ctx_2 = store_2.context();

        // 2. The new state uses the same private and signing keys
        let verifying_key_before_rotation = ctx
            .get_verifying_key(SigningKeyId::UserSigningKey)
            .expect("Signing key should be present in context before rotation");
        let verifying_key_after_rotation = ctx_2
            .get_verifying_key(SigningKeyId::UserSigningKey)
            .expect("Signing key should be present in context after rotation");
        assert_eq!(
            verifying_key_before_rotation.to_cose(),
            verifying_key_after_rotation.to_cose(),
            "Signing key should be preserved during rotation from V2 to V2"
        );

        let public_key_before_rotation = ctx
            .get_public_key(PrivateKeyId::UserPrivateKey)
            .expect("Private key should be present in context before rotation");
        let public_key_after_rotation = ctx_2
            .get_public_key(PrivateKeyId::UserPrivateKey)
            .expect("Private key should be present in context after rotation");
        assert_eq!(
            public_key_before_rotation.to_der().unwrap(),
            public_key_after_rotation.to_der().unwrap(),
            "Private key should be preserved during rotation from V2 to V2"
        );
    }
}
