#[cfg(feature = "internal")]
use std::sync::RwLock;

#[cfg(feature = "internal")]
use bitwarden_crypto::{
    Aes256CbcHmacKey, AsymmetricCryptoKey, CoseKeyBytes, CoseSerializable, EncString,
    KeyDecryptable, Pkcs8PrivateKeyBytes, SigningKey, UnsignedSharedKey, XChaCha20Poly1305Key,
};
#[cfg(any(feature = "internal", feature = "secrets"))]
use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
use bitwarden_error::bitwarden_error;
#[cfg(feature = "internal")]
use log::warn;
use thiserror::Error;

#[cfg(any(feature = "secrets", feature = "internal"))]
use crate::OrganizationId;
#[cfg(feature = "internal")]
use crate::key_management::{AsymmetricKeyId, SecurityState, SignedSecurityState, SigningKeyId};
#[cfg(any(feature = "internal", feature = "secrets"))]
use crate::key_management::{KeyIds, SymmetricKeyId};
use crate::{MissingPrivateKeyError, error::UserIdAlreadySetError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptionSettingsError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid signing key")]
    InvalidSigningKey,

    #[error("Invalid security state")]
    InvalidSecurityState,

    #[error(transparent)]
    MissingPrivateKey(#[from] MissingPrivateKeyError),

    #[error(transparent)]
    UserIdAlreadySet(#[from] UserIdAlreadySetError),

    #[error("Wrong Pin")]
    WrongPin,
}

#[allow(clippy::large_enum_variant)]
#[cfg(feature = "internal")]
pub(crate) enum AccountEncryptionKeys {
    V1 {
        user_key: Aes256CbcHmacKey,
        private_key: EncString,
    },
    V2 {
        user_key: XChaCha20Poly1305Key,
        private_key: EncString,
        signing_key: EncString,
        security_state: SignedSecurityState,
    },
}

#[allow(missing_docs)]
pub struct EncryptionSettings {}

impl EncryptionSettings {
    /// Initialize the encryption settings with the decrypted user key and the encrypted user
    /// private key This should only be used when unlocking the vault via biometrics or when the
    /// vault is set to lock: "never" Otherwise handling the decrypted user key is dangerous and
    /// discouraged
    #[cfg(feature = "internal")]
    pub(crate) fn new_decrypted_key(
        encryption_keys: AccountEncryptionKeys,
        store: &KeyStore<KeyIds>,
        security_state_rwlock: &RwLock<Option<SecurityState>>,
    ) -> Result<(), EncryptionSettingsError> {
        // This is an all-or-nothing check. The server cannot pretend a signing key or security
        // state to be missing, because they are *always* present when the user key is an
        // XChaCha20Poly1305Key. Thus, the server or network cannot lie about the presence of these,
        // because otherwise the entire user account will fail to decrypt.
        match encryption_keys {
            AccountEncryptionKeys::V1 {
                user_key,
                private_key,
            } => {
                Self::init_v1(user_key, private_key, store)?;
            }
            AccountEncryptionKeys::V2 {
                user_key,
                private_key,
                signing_key,
                security_state,
            } => {
                Self::init_v2(
                    user_key,
                    private_key,
                    signing_key,
                    security_state,
                    store,
                    security_state_rwlock,
                )?;
            }
        }

        Ok(())
    }

    #[cfg(feature = "internal")]
    fn init_v1(
        user_key: Aes256CbcHmacKey,
        private_key: EncString,
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        let user_key = SymmetricCryptoKey::Aes256CbcHmacKey(user_key);

        let private_key = {
            let dec: Vec<u8> = private_key.decrypt_with_key(&user_key)?;

            // FIXME: [PM-11690] - Temporarily ignore invalid private keys until we have a
            // recovery process in place.
            AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(dec))
                .map_err(|_| {
                    warn!("Invalid private key");
                })
                .ok()

            // Some(
            //     AsymmetricCryptoKey::from_der(&dec)
            //         .map_err(|_| EncryptionSettingsError::InvalidPrivateKey)?,
            // )
        };

        // FIXME: [PM-18098] When this is part of crypto we won't need to use deprecated methods
        #[allow(deprecated)]
        {
            let mut ctx = store.context_mut();
            ctx.set_symmetric_key(SymmetricKeyId::User, user_key)?;
            if let Some(private_key) = private_key {
                ctx.set_asymmetric_key(AsymmetricKeyId::UserPrivateKey, private_key)?;
            }
        }

        Ok(())
    }

    #[cfg(feature = "internal")]
    fn init_v2(
        user_key: XChaCha20Poly1305Key,
        private_key: EncString,
        signing_key: EncString,
        security_state: SignedSecurityState,
        store: &KeyStore<KeyIds>,
        sdk_security_state: &RwLock<Option<SecurityState>>,
    ) -> Result<(), EncryptionSettingsError> {
        use crate::key_management::SecurityState;

        let user_key = SymmetricCryptoKey::XChaCha20Poly1305Key(user_key);

        // For v2 users, we mandate the signing key and security state and the private key to be
        // present and valid Everything MUST decrypt.
        let signing_key: Vec<u8> = signing_key.decrypt_with_key(&user_key)?;
        let signing_key = SigningKey::from_cose(&CoseKeyBytes::from(signing_key))
            .map_err(|_| EncryptionSettingsError::InvalidSigningKey)?;
        let private_key: Vec<u8> = private_key.decrypt_with_key(&user_key)?;
        let private_key = AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(private_key))
            .map_err(|_| EncryptionSettingsError::InvalidPrivateKey)?;

        let security_state: SecurityState = security_state
            .verify_and_unwrap(&signing_key.to_verifying_key())
            .map_err(|_| EncryptionSettingsError::InvalidSecurityState)?;
        *sdk_security_state.write().expect("RwLock not poisoned") = Some(security_state);

        #[allow(deprecated)]
        {
            let mut ctx = store.context_mut();
            ctx.set_symmetric_key(SymmetricKeyId::User, user_key)?;
            ctx.set_asymmetric_key(AsymmetricKeyId::UserPrivateKey, private_key)?;
            ctx.set_signing_key(SigningKeyId::UserSigningKey, signing_key)?;
        }

        Ok(())
    }

    /// Initialize the encryption settings with only a single decrypted organization key.
    /// This is used only for logging in Secrets Manager with an access token
    #[cfg(feature = "secrets")]
    pub(crate) fn new_single_org_key(
        organization_id: OrganizationId,
        key: SymmetricCryptoKey,
        store: &KeyStore<KeyIds>,
    ) {
        // FIXME: [PM-18098] When this is part of crypto we won't need to use deprecated methods
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(SymmetricKeyId::Organization(organization_id), key)
            .expect("Mutable context");
    }

    #[cfg(feature = "internal")]
    pub(crate) fn set_org_keys(
        org_enc_keys: Vec<(OrganizationId, UnsignedSharedKey)>,
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        use crate::key_management::AsymmetricKeyId;

        let mut ctx = store.context_mut();

        // FIXME: [PM-11690] - Early abort to handle private key being corrupt
        if org_enc_keys.is_empty() {
            return Ok(());
        }

        if !ctx.has_asymmetric_key(AsymmetricKeyId::UserPrivateKey) {
            return Err(MissingPrivateKeyError.into());
        }

        // Make sure we only keep the keys given in the arguments and not any of the previous
        // ones, which might be from organizations that the user is no longer a part of anymore
        ctx.retain_symmetric_keys(|key_ref| !matches!(key_ref, SymmetricKeyId::Organization(_)));

        // Decrypt the org keys with the private key
        for (org_id, org_enc_key) in org_enc_keys {
            ctx.decapsulate_key_unsigned(
                AsymmetricKeyId::UserPrivateKey,
                SymmetricKeyId::Organization(org_id),
                &org_enc_key,
            )?;
        }

        Ok(())
    }
}
