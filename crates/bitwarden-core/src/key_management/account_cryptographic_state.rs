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

use bitwarden_api_api::models::{PrivateKeysResponseModel, SecurityStateModel};
use bitwarden_crypto::{
    AsymmetricPublicCryptoKey, CoseSerializable, CryptoError, EncString, KeyStore, KeyStoreContext,
    PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SignedPublicKey, SymmetricKeyAlgorithm,
    VerifyingKey,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use log::info;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    UserId,
    key_management::{
        AsymmetricKeyId, KeyIds, SecurityState, SignedSecurityState, SigningKeyId, SymmetricKeyId,
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

/// Any keys / cryptographic protection "downstream" from the account symmetric key (user key).
/// Private keys are protected by the user key.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl WrappedAccountCryptographicState {
    /// Converts to a PrivateKeysResponseModel in order to make API requests. Since the
    /// [WrappedAccountCryptographicState] is encrypted, the key store needs to contain the
    /// user key required to unlock this state.
    pub fn to_private_keys_request_model(
        &self,
        store: &KeyStore<KeyIds>,
    ) -> Result<PrivateKeysResponseModel, AccountCryptographyInitializationError> {
        let verifying_key = self.verifying_key(store)?;
        Ok(PrivateKeysResponseModel {
            object: Some("privateKeys".to_string()),
            signature_key_pair: match self {
                WrappedAccountCryptographicState::V1 { .. } => None,
                WrappedAccountCryptographicState::V2 { signing_key, .. } => Some(Box::new(
                    bitwarden_api_api::models::SignatureKeyPairResponseModel {
                        wrapped_signing_key: Some(signing_key.to_string()),
                        verifying_key: Some(
                            B64::from(
                                verifying_key
                                    .as_ref()
                                    .map(|vk| vk.to_cose())
                                    .ok_or(AccountCryptographyInitializationError::CorruptData)?,
                            )
                            .to_string(),
                        ),
                        object: Some("signatureKeyPair".to_string()),
                    },
                )),
            },
            public_key_encryption_key_pair: Box::new(
                bitwarden_api_api::models::PublicKeyEncryptionKeyPairResponseModel {
                    wrapped_private_key: match self {
                        WrappedAccountCryptographicState::V1 { private_key } => {
                            Some(private_key.to_string())
                        }
                        WrappedAccountCryptographicState::V2 { private_key, .. } => {
                            Some(private_key.to_string())
                        }
                    },
                    public_key: match self.public_key(store) {
                        Ok(Some(pk)) => Some(B64::from(pk.to_der()?).to_string()),
                        _ => None,
                    },
                    signed_public_key: match self.signed_public_key() {
                        Ok(Some(spk)) => Some(spk.clone().into()),
                        _ => None,
                    },
                    object: Some("publicKeyEncryptionKeyPair".to_string()),
                },
            ),
            security_state: match self {
                WrappedAccountCryptographicState::V1 { .. } => None,
                WrappedAccountCryptographicState::V2 { security_state, .. } => {
                    // ensure we have a verifying key reference and convert the verified state's
                    // version to i32 for the API model
                    let vk_ref = verifying_key
                        .as_ref()
                        .ok_or(AccountCryptographyInitializationError::CorruptData)?;
                    Some(Box::new(SecurityStateModel {
                        security_state: Some(security_state.into()),
                        security_version: security_state
                            .clone()
                            .verify_and_unwrap(vk_ref)
                            .map_err(|_| AccountCryptographyInitializationError::TamperedData)?
                            .version() as i32,
                    }))
                }
            },
        })
    }

    /// Creates a new V2 account cryptographic state with fresh keys.This does not change the user
    /// state, but does set some keys to the local context.
    pub fn make(
        ctx: &mut KeyStoreContext<KeyIds>,
        user_id: UserId,
    ) -> Result<(SymmetricKeyId, Self), AccountCryptographyInitializationError> {
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1)?;
        let signing_key = ctx.make_signing_key(SignatureAlgorithm::Ed25519)?;
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

    /// Set the decrypted account cryptographic state to the context's non-local storage.
    /// This needs a mutable context passed in that already has a user_key set to a local key slot,
    /// for which che id is passed in as `user_key`. Note, that this function drops the context
    /// and clears the existing local state, after persisting it.
    pub(crate) fn set_to_context(
        &self,
        security_state_rwlock: &RwLock<Option<SecurityState>>,
        user_key: SymmetricKeyId,
        store: &KeyStore<KeyIds>,
        mut ctx: KeyStoreContext<KeyIds>,
    ) -> Result<(), AccountCryptographyInitializationError> {
        if ctx.has_symmetric_key(SymmetricKeyId::User)
            || ctx.has_asymmetric_key(AsymmetricKeyId::UserPrivateKey)
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

                let private_key_id = ctx
                    .unwrap_private_key(user_key, private_key)
                    .map_err(|_| AccountCryptographyInitializationError::WrongUserKey)?;

                ctx.persist_asymmetric_key(private_key_id, AsymmetricKeyId::UserPrivateKey)?;
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
                ctx.persist_asymmetric_key(private_key_id, AsymmetricKeyId::UserPrivateKey)?;
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

    /// Retrieve the verifying key from the wrapped state, if present. This requires the user key to
    /// be present in the store.
    fn verifying_key(
        &self,
        store: &KeyStore<KeyIds>,
    ) -> Result<Option<VerifyingKey>, AccountCryptographyInitializationError> {
        match self {
            WrappedAccountCryptographicState::V1 { .. } => Ok(None),
            WrappedAccountCryptographicState::V2 { signing_key, .. } => {
                let mut ctx = store.context_mut();
                let signing_key = ctx
                    .unwrap_signing_key(SymmetricKeyId::User, signing_key)
                    .map_err(|_| AccountCryptographyInitializationError::WrongUserKey)?;
                ctx.get_verifying_key(signing_key)
                    .map(Some)
                    .map_err(|e| e.into())
            }
        }
    }

    /// Retrieve the public key from the wrapped state, if present. This requires the user key to
    /// be present in the store.
    fn public_key(
        &self,
        store: &KeyStore<KeyIds>,
    ) -> Result<Option<AsymmetricPublicCryptoKey>, AccountCryptographyInitializationError> {
        match self {
            WrappedAccountCryptographicState::V1 { private_key }
            | WrappedAccountCryptographicState::V2 { private_key, .. } => {
                let mut ctx = store.context_mut();
                let private_key = ctx
                    .unwrap_private_key(SymmetricKeyId::User, private_key)
                    .map_err(|_| AccountCryptographyInitializationError::WrongUserKey)?;
                ctx.get_public_key(private_key)
                    .map(Some)
                    .map_err(|e| e.into())
            }
        }
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

    use bitwarden_crypto::KeyStore;

    use super::*;
    use crate::key_management::{AsymmetricKeyId, SigningKeyId, SymmetricKeyId};

    #[test]
    fn test_set_to_context_v1() {
        // Prepare a temporary store to create wrapped state using a known user key
        let temp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut temp_ctx = temp_store.context_mut();

        // Create a V1-style user key (Aes256CbcHmac) and add to temp context
        let user_key = temp_ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Make a private key and wrap it with the user key
        let private_key_id = temp_ctx
            .make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1)
            .unwrap();
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
        assert!(ctx.has_asymmetric_key(AsymmetricKeyId::UserPrivateKey));
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
        let private_key_id = temp_ctx
            .make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1)
            .unwrap();
        let signing_key_id = temp_ctx
            .make_signing_key(SignatureAlgorithm::Ed25519)
            .unwrap();
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
                .has_asymmetric_key(AsymmetricKeyId::UserPrivateKey)
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
        let model = wrapped_account_cryptography_state
            .to_private_keys_request_model(&temp_store)
            .expect("to_private_keys_request_model should succeed");

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

        let pk_pair = model.public_key_encryption_key_pair;
        assert_eq!(
            pk_pair.public_key.unwrap(),
            B64::from(
                ctx.get_public_key(AsymmetricKeyId::UserPrivateKey)
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
}
