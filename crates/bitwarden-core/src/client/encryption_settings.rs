#[cfg(any(feature = "internal", feature = "secrets"))]
use bitwarden_crypto::KeyStore;
#[cfg(feature = "secrets")]
use bitwarden_crypto::SymmetricCryptoKey;
#[cfg(feature = "internal")]
use bitwarden_crypto::UnsignedSharedKey;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "internal")]
use tracing::{info, instrument};

#[cfg(any(feature = "secrets", feature = "internal"))]
use crate::OrganizationId;
#[cfg(any(feature = "internal", feature = "secrets"))]
use crate::key_management::{KeyIds, SymmetricKeyId};
use crate::{MissingPrivateKeyError, error::UserIdAlreadySetError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptionSettingsError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    #[error("Cryptography Initialization error")]
    CryptoInitialization,

    #[error(transparent)]
    MissingPrivateKey(#[from] MissingPrivateKeyError),

    #[error(transparent)]
    UserIdAlreadySet(#[from] UserIdAlreadySetError),

    #[error("Wrong Pin")]
    WrongPin,
}

#[allow(missing_docs)]
pub struct EncryptionSettings {}

impl EncryptionSettings {
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
    #[instrument(err, skip_all)]
    pub(crate) fn set_org_keys(
        org_enc_keys: Vec<(OrganizationId, UnsignedSharedKey)>,
        store: &KeyStore<KeyIds>,
    ) -> Result<(), EncryptionSettingsError> {
        use crate::key_management::PrivateKeyId;

        let mut ctx = store.context_mut();

        // FIXME: [PM-11690] - Early abort to handle private key being corrupt
        if org_enc_keys.is_empty() {
            info!("No organization keys to set");
            return Ok(());
        }

        if !ctx.has_private_key(PrivateKeyId::UserPrivateKey) {
            info!("User private key is missing, cannot set organization keys");
            return Err(MissingPrivateKeyError.into());
        }

        // Make sure we only keep the keys given in the arguments and not any of the previous
        // ones, which might be from organizations that the user is no longer a part of anymore
        ctx.retain_symmetric_keys(|key_ref| !matches!(key_ref, SymmetricKeyId::Organization(_)));

        info!("Decrypting organization keys");
        // Decrypt the org keys with the private key
        for (org_id, org_enc_key) in org_enc_keys {
            let _span =
                tracing::span!(tracing::Level::INFO, "decapsulate_org_key", org_id = %org_id)
                    .entered();
            ctx.decapsulate_key_unsigned(
                PrivateKeyId::UserPrivateKey,
                SymmetricKeyId::Organization(org_id),
                &org_enc_key,
            ) {
                tracing::error!("Failed to decapsulate organization key: {}", e);
                return Err(e.into());
            } else {
                tracing::info!("Successfully decapsulated organization key");
            }
        }

        Ok(())
    }
}
