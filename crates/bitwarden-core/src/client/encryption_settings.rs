use bitwarden_crypto::{AsymmetricCryptoKey, KeyStore, SymmetricCryptoKey};
#[cfg(feature = "internal")]
use bitwarden_crypto::{AsymmetricEncString, EncString};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "internal")]
use crate::error::Result;
use crate::{
    key_management::{AsymmetricKeyId, KeyIds, SymmetricKeyId},
    VaultLockedError,
};

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

    #[error("Missing private key")]
    MissingPrivateKey,
}

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
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        use bitwarden_crypto::KeyDecryptable;
        use log::warn;

        use crate::key_management::{AsymmetricKeyId, SymmetricKeyId};

        let private_key = {
            let dec: Vec<u8> = private_key.decrypt_with_key(&user_key)?;

            // FIXME: [PM-11690] - Temporarily ignore invalid private keys until we have a recovery
            // process in place.
            AsymmetricCryptoKey::from_der(&dec)
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

    /// Initialize the encryption settings with only a single decrypted key.
    /// This is used only for logging in Secrets Manager with an access token
    #[cfg(feature = "secrets")]
    pub(crate) fn new_single_key(key: SymmetricCryptoKey, store: &KeyStore<KeyIds>) {
        // FIXME: [PM-18098] When this is part of crypto we won't need to use deprecated methods
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(SymmetricKeyId::User, key)
            .expect("Mutable context");
    }

    #[cfg(feature = "internal")]
    pub(crate) fn set_org_keys(
        org_enc_keys: Vec<(Uuid, AsymmetricEncString)>,
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        let mut ctx = store.context_mut();

        // FIXME: [PM-11690] - Early abort to handle private key being corrupt
        if org_enc_keys.is_empty() {
            return Ok(());
        }

        if !ctx.has_asymmetric_key(AsymmetricKeyId::UserPrivateKey) {
            return Err(EncryptionSettingsError::MissingPrivateKey);
        }

        // Make sure we only keep the keys given in the arguments and not any of the previous
        // ones, which might be from organizations that the user is no longer a part of anymore
        ctx.retain_symmetric_keys(|key_ref| !matches!(key_ref, SymmetricKeyId::Organization(_)));

        // Decrypt the org keys with the private key
        for (org_id, org_enc_key) in org_enc_keys {
            ctx.decrypt_symmetric_key_with_asymmetric_key(
                AsymmetricKeyId::UserPrivateKey,
                SymmetricKeyId::Organization(org_id),
                &org_enc_key,
            )?;
        }

        Ok(())
    }
}
