use bitwarden_crypto::{
    KeySlotIds, KeyStoreContext, SymmetricCryptoKey,
    safe::{SymmetricKeyEnvelope, SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace},
};

/// A symmetric key that wraps the user key in the persisted state, allowing a
/// rehydrated client to unlock without re-deriving the user key from a master
/// password or other primary unlock factor.
///
/// Callers are responsible for storing this key in a secure location outside
/// the SDK (e.g. the OS keychain) and providing it back to
/// [`LockingClient::unlock`](crate::LockingClient::unlock) when reconstructing
/// the client.
#[derive(PartialEq)] // This is ok because SymmetricCryptoKey implements PartialEq with constant-time equality checks.
pub struct SessionKey(pub(crate) SymmetricCryptoKey);

impl SessionKey {
    /// Mint a new random session key.
    pub fn make() -> Self {
        Self(SymmetricCryptoKey::make_xchacha20_poly1305_key())
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
