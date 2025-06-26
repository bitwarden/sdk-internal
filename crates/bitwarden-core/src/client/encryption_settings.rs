#[cfg(feature = "internal")]
use bitwarden_crypto::{EncString, UnsignedSharedKey};
#[cfg(any(feature = "internal", feature = "secrets"))]
use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(any(feature = "internal", feature = "secrets"))]
use uuid::Uuid;

#[cfg(any(feature = "internal", feature = "secrets"))]
use crate::key_management::{KeyIds, SymmetricKeyId};
use crate::{error::UserIdAlreadySetError, MissingPrivateKeyError, VaultLockedError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptionSettingsError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),

    #[error(transparent)]
    VaultLocked(#[from] VaultLockedError),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid signing key")]
    InvalidSigningKey,

    #[error(transparent)]
    MissingPrivateKey(#[from] MissingPrivateKeyError),

    #[error(transparent)]
    UserIdAlreadySetError(#[from] UserIdAlreadySetError),
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
        user_key: SymmetricCryptoKey,
        private_key: EncString,
        signing_key: Option<EncString>,
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        use bitwarden_crypto::{AsymmetricCryptoKey, CoseSerializable, KeyDecryptable, SigningKey};
        use log::warn;

        use crate::key_management::{AsymmetricKeyId, SigningKeyId, SymmetricKeyId};

        let private_key = {
            let dec: Vec<u8> = private_key.decrypt_with_key(&user_key)?;
            // FIXME: [PM-11690] - Temporarily ignore invalid private keys until we have a recovery
            // process in place.
            AsymmetricCryptoKey::from_der(&dec.into())
                .map_err(|_| {
                    warn!("Invalid private key");
                })
                .ok()

            // Some(
            //     AsymmetricCryptoKey::from_der(&dec)
            //         .map_err(|_| EncryptionSettingsError::InvalidPrivateKey)?,
            // )
        };
        let signing_key = signing_key
            .map(|key| {
                use bitwarden_crypto::CryptoError;

                let dec: Vec<u8> = key.decrypt_with_key(&user_key)?;
                SigningKey::from_cose(&dec.into()).map_err(Into::<CryptoError>::into)
            })
            .transpose()?;

        // FIXME: [PM-18098] When this is part of crypto we won't need to use deprecated methods
        #[allow(deprecated)]
        {
            let mut ctx = store.context_mut();
            ctx.set_symmetric_key(SymmetricKeyId::User, user_key)?;
            if let Some(private_key) = private_key {
                ctx.set_asymmetric_key(AsymmetricKeyId::UserPrivateKey, private_key)?;
            }

            if let Some(signing_key) = signing_key {
                ctx.set_signing_key(SigningKeyId::UserSigningKey, signing_key)?;
            }
        }

        Ok(())
    }

    /// Initialize the encryption settings with only a single decrypted organization key.
    /// This is used only for logging in Secrets Manager with an access token
    #[cfg(feature = "secrets")]
    pub(crate) fn new_single_org_key(
        organization_id: Uuid,
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
        org_enc_keys: Vec<(Uuid, UnsignedSharedKey)>,
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
