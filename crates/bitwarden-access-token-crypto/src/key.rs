//! The symmetric key derived from an access-token seed.

use std::fmt;

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeySlotIds, KeyStoreContext,
    SymmetricCryptoKey, derive_shareable_key,
};
use bitwarden_encoding::B64;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{AccessTokenError, AccessTokenSeed, purpose::KeyPurpose};

/// Becomes the HKDF salt `bitwarden-accesstoken`, shared by every [`KeyPurpose`].
pub(crate) const DERIVE_NAME: &str = "accesstoken";

/// A key derived from an [`AccessTokenSeed`] for one [`KeyPurpose`]. The raw key never leaves this
/// crate; [`Self::open_payload`] installs what it unwraps straight into a [`KeyStoreContext`].
pub struct AccessTokenKey(SymmetricCryptoKey);

impl fmt::Debug for AccessTokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessTokenKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl AccessTokenKey {
    /// Deterministically derives the key for `purpose` from `seed`.
    pub fn derive(seed: &AccessTokenSeed, purpose: KeyPurpose) -> Self {
        Self(SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            Zeroizing::new(*seed.as_bytes()),
            DERIVE_NAME,
            Some(purpose.as_str()),
        )))
    }

    /// Decrypts `encrypted_payload` and installs the organization key it carries at
    /// `organization_key` in `ctx`. Errors carry no payload content.
    pub fn open_payload<Ids: KeySlotIds>(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        encrypted_payload: &str,
        organization_key: Ids::Symmetric,
    ) -> Result<(), AccessTokenError> {
        let encrypted_payload: EncString = encrypted_payload
            .parse()
            .map_err(|_| AccessTokenError::InvalidPayload)?;

        let decrypted: Vec<u8> = encrypted_payload
            .decrypt_with_key(&self.0)
            .map_err(|_| AccessTokenError::InvalidPayload)?;

        #[derive(Deserialize)]
        struct Payload {
            #[serde(rename = "encryptionKey")]
            encryption_key: B64,
        }

        let payload: Payload =
            serde_json::from_slice(&decrypted).map_err(|_| AccessTokenError::InvalidPayload)?;

        let key_bytes = BitwardenLegacyKeyBytes::from(&payload.encryption_key);
        let key = SymmetricCryptoKey::try_from(&key_bytes)
            .map_err(|_| AccessTokenError::InvalidOrgKey)?;

        let local = ctx.add_local_symmetric_key(key);
        ctx.persist_symmetric_key(local, organization_key)?;
        Ok(())
    }
}

#[cfg(test)]
impl AccessTokenKey {
    pub(crate) fn to_base64_for_tests(&self) -> String {
        self.0.to_base64().to_string()
    }
}
