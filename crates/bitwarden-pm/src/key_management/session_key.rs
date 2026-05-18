use std::{fmt::Display, str::FromStr};

use bitwarden_crypto::{CryptoError, SymmetricCryptoKey};

/// A symmetric key that wraps the user key in the persisted state, allowing a
/// rehydrated client to unlock without re-deriving the user key from a master
/// password or other primary unlock factor.
///
/// Callers are responsible for storing this key in a secure location outside
/// the SDK (e.g. the OS keychain) and providing it back to
/// [`PasswordManagerClient::unlock`](crate::PasswordManagerClient::unlock) when
/// reconstructing the client.
pub struct SessionKey(pub(super) SymmetricCryptoKey);

impl SessionKey {
    /// Mint a new random session key.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(SymmetricCryptoKey::make_xchacha20_poly1305_key())
    }
}

impl Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0.to_base64(), f)
    }
}

impl FromStr for SessionKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(SymmetricCryptoKey::try_from(s.to_string())?))
    }
}
