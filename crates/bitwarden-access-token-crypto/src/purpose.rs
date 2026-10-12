//! The HKDF `info` that separates key-derivation purposes.

/// The purpose a key is derived for from an [`crate::AccessTokenSeed`].
///
/// Each purpose maps to an HKDF `info` string. The strings must be unique (colliding purposes
/// derive the same key) and must never change once credentials are issued under them (they would
/// derive a different key). Adding a purpose is a deliberate change that requires review by this
/// crate's owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// The PAM access connector.
    AccessConnector,
    /// Secrets Manager access tokens.
    SecretsManager,
}

impl KeyPurpose {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::AccessConnector => "access-connector",
            Self::SecretsManager => "sm-access-token",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Changing either string would change the key already-issued tokens derive.
    #[test]
    fn key_purposes_are_pinned() {
        assert_eq!(KeyPurpose::AccessConnector.as_str(), "access-connector");
        assert_eq!(KeyPurpose::SecretsManager.as_str(), "sm-access-token");
    }
}
