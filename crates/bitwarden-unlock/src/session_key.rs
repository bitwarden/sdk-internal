use bitwarden_crypto::SymmetricCryptoKey;

/// A symmetric key that wraps the user key in the persisted state, allowing a
/// rehydrated client to unlock without re-deriving the user key from a master
/// password or other primary unlock factor.
///
/// Callers are responsible for storing this key in a secure location outside
/// the SDK (e.g. the OS keychain) and providing it back to
/// [`UnlockClient::unlock`](crate::UnlockClient::unlock) when reconstructing
/// the client.
pub struct SessionKey(pub(crate) SymmetricCryptoKey);

impl SessionKey {
    /// Mint a new random session key.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(SymmetricCryptoKey::make_xchacha20_poly1305_key())
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        // This is ok because SymmetricCryptoKey implements PartialEq with constant-time equality
        // checks.
        self.0 == other.0
    }
}
