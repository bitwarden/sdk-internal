use crate::BitwardenClient;

/// Provides anonymous authentication / authorization methods.
pub struct AuthClient {
    /// The underlying client that this [`AuthClient`] uses.
    pub client: bitwarden_core::Client,
}

impl BitwardenClient {
    /// Convenience method on [`BitwardenClient`] to access the [`AuthClient`].
    ///
    /// # Example of usage
    ///
    /// ```rust
    /// let client = BitwardenClient::new(None);
    /// let auth_client = client.auth();
    /// ```
    ///
    /// # Example of usage without this method
    /// ```rust
    /// let auth_client = AuthClient {
    ///     client: client.clone(),
    /// };
    /// ```
    ///
    /// # Returns
    /// A new instance of [`AuthClient`].
    pub fn auth(&self) -> AuthClient {
        AuthClient {
            client: self.0.clone(),
        }
    }
}
