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

/// Key-derivation name, which `derive_shareable_key` turns into the HKDF salt
/// `bitwarden-accesstoken`. Shared across every [`crate::KeyPurpose`]; the HKDF `info` is what
/// separates them.
pub(crate) const DERIVE_NAME: &str = "accesstoken";

/// A symmetric key derived from an [`AccessTokenSeed`] for one [`KeyPurpose`]. The raw key never
/// leaves this crate's API: the only operation exposed on it is [`Self::open_payload`], which
/// installs the organization key it unwraps straight into a [`KeyStoreContext`] slot.
pub struct AccessTokenKey(SymmetricCryptoKey);

// Redacts the key; nothing about it is safe to log.
impl fmt::Debug for AccessTokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessTokenKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl AccessTokenKey {
    /// Derives the key for `purpose` from `seed`. Deterministic: the same seed and purpose always
    /// derive the same key, and distinct purposes derive distinct keys from the same seed.
    pub fn derive(seed: &AccessTokenSeed, purpose: KeyPurpose) -> Self {
        Self(SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            Zeroizing::new(*seed.as_bytes()),
            DERIVE_NAME,
            Some(purpose.as_str()),
        )))
    }

    /// Decrypts `encrypted_payload` with this key, recovers the organization key it carries, and
    /// installs it at `organization_key` in `ctx`.
    ///
    /// The key material never leaves the store, and errors carry no payload content.
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
    /// Test-only accessor for the derived key's base64, since the raw key is otherwise private so
    /// it never leaves this crate's API in production code paths.
    pub(crate) fn to_base64_for_tests(&self) -> String {
        self.0.to_base64().to_string()
    }
}
