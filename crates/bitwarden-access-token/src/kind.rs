//! The client-kind segment of an access token.

use bitwarden_access_token_crypto::KeyPurpose;

/// Which kind of unattended client a [`crate::AccessToken`] authenticates. Each variant's
/// [`segment`](AccessTokenKind::segment) is the token's `<client-kind>` wire segment and must
/// match the issuing server's provider prefix for that client, or tokens parse but cannot
/// authenticate. `None` means the format has no such segment (Secrets Manager's three-part
/// format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTokenKind {
    /// The PAM access connector.
    AccessConnector,
    /// Secrets Manager. Tokens have no client-kind segment:
    /// `0.<api-key-id>.<client-secret>:<seed>`.
    SecretsManager,
}

impl AccessTokenKind {
    /// The token's `<client-kind>` wire segment for this kind, or `None` if the format omits it.
    pub fn segment(&self) -> Option<&'static str> {
        match self {
            Self::AccessConnector => Some("access-connector"),
            Self::SecretsManager => None,
        }
    }

    /// The key-derivation purpose for this kind. `SecretsManager`'s string must stay
    /// byte-identical with the clients' web vault, which mints Secrets Manager access tokens
    /// independently of this crate.
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

    /// If this fails, check the server's `PamAccessConnectorClientProvider.AccessConnectorPrefix`
    /// before changing it, since a mismatch yields tokens that parse but cannot authenticate.
    #[test]
    fn access_connector_matches_the_servers_provider_prefix() {
        assert_eq!(
            AccessTokenKind::AccessConnector.segment(),
            Some("access-connector")
        );
    }

    /// Secrets Manager's three-part format has no client-kind segment.
    #[test]
    fn secrets_manager_has_no_segment() {
        assert_eq!(AccessTokenKind::SecretsManager.segment(), None);
    }

    /// Both purposes are pinned by equality: changing either string would silently change which
    /// key already-issued tokens of that kind derive.
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
