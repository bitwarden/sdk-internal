//! The client-kind segment of an access token.

use bitwarden_access_token_crypto::KeyPurpose;

/// Which kind of unattended client a [`crate::AccessToken`] authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTokenKind {
    /// The PAM access connector.
    AccessConnector,
    /// Secrets Manager, whose tokens have no client-kind segment.
    SecretsManager,
}

impl AccessTokenKind {
    /// The `<client-kind>` wire segment, or `None` if the format omits it.
    pub fn segment(&self) -> Option<&'static str> {
        match self {
            Self::AccessConnector => Some("access-connector"),
            Self::SecretsManager => None,
        }
    }

    /// The key-derivation purpose. `SecretsManager`'s must match the web vault, which mints Secrets
    /// Manager tokens independently.
    pub fn key_purpose(&self) -> KeyPurpose {
        match self {
            Self::AccessConnector => KeyPurpose::new("access-connector"),
            Self::SecretsManager => KeyPurpose::new("sm-access-token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Must match the server's `PamAccessConnectorClientProvider.AccessConnectorPrefix`, or tokens
    /// parse but cannot authenticate.
    #[test]
    fn access_connector_matches_the_servers_provider_prefix() {
        assert_eq!(
            AccessTokenKind::AccessConnector.segment(),
            Some("access-connector")
        );
    }

    #[test]
    fn secrets_manager_has_no_segment() {
        assert_eq!(AccessTokenKind::SecretsManager.segment(), None);
    }

    /// Changing either string would change the key already-issued tokens derive.
    #[test]
    fn key_purposes_are_pinned() {
        assert_eq!(
            AccessTokenKind::SecretsManager.key_purpose(),
            KeyPurpose::new("sm-access-token")
        );
        assert_eq!(
            AccessTokenKind::AccessConnector.key_purpose(),
            KeyPurpose::new("access-connector")
        );
    }
}
