//! The client-kind segment of an access token.

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

    /// The HKDF `info` parameter for this kind's key derivation. `SecretsManager`'s must stay
    /// byte-identical with the clients' web vault, which mints Secrets Manager access tokens
    /// independently of this crate.
    pub(crate) fn derive_info(&self) -> &'static str {
        match self {
            Self::AccessConnector => "access-connector",
            Self::SecretsManager => "sm-access-token",
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
}
