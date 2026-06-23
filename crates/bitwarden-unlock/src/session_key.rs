use std::{fmt::Display, str::FromStr};

use bitwarden_crypto::{
    CryptoError, KeySlotIds, KeyStoreContext, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    safe::{SymmetricKeyEnvelope, SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace},
};

/// A symmetric key that wraps the user key in the persisted state, allowing a
/// rehydrated client to unlock without re-deriving the user key from a master
/// password or other primary unlock factor.
///
/// Callers are responsible for storing this key in a secure location outside
/// the SDK (e.g. the OS keychain) and providing it back to
/// [`UnlockClient::unlock`](crate::UnlockClient::unlock) when reconstructing
/// the client.
#[derive(PartialEq, Clone)] // This is ok because SymmetricCryptoKey implements PartialEq with constant-time equality checks.
pub struct SessionKey(pub(crate) SymmetricCryptoKey);

impl SessionKey {
    /// Mint a new random session key.
    pub fn make() -> Self {
        Self(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::XChaCha20Poly1305,
        ))
    }

    /// Mint a new session key, seal `key_to_seal` (already present in `ctx`)
    /// with it, and return both the envelope and the new session key.
    pub fn from_context<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(SymmetricKeyEnvelope, SessionKey), SymmetricKeyEnvelopeError> {
        let session_key = SessionKey::make();
        let session_key_id = ctx.add_local_symmetric_key(session_key.0.clone());
        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            session_key_id,
            SymmetricKeyEnvelopeNamespace::SessionKey,
            ctx,
        )?;
        Ok((envelope, session_key))
    }

    /// Unseal `envelope` using this session key and place the resulting key in
    /// `ctx`, returning the local id under which it is registered.
    pub fn unwrap_to_context<Ids: KeySlotIds>(
        &self,
        envelope: &SymmetricKeyEnvelope,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SymmetricKeyEnvelopeError> {
        let session_key_id = ctx.add_local_symmetric_key(self.0.clone());
        envelope.unseal(
            session_key_id,
            SymmetricKeyEnvelopeNamespace::SessionKey,
            ctx,
        )
    }
}

impl FromStr for SessionKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SessionKey(s.parse()?))
    }
}

impl Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.to_base64().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_roundtrip_recovers_session_key() {
        let original = SessionKey::make();
        let encoded = original.0.to_base64().to_string();

        let parsed: SessionKey = encoded.parse().unwrap();
        assert!(parsed == original);
    }

    #[test]
    fn from_str_rejects_invalid_base64() {
        let result: Result<SessionKey, _> = "not-a-valid-key".parse();
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }
}
