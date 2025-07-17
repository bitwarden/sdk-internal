use crate::Client;

/// Provides anonymous authentication / authorization methods.
pub struct AuthClient {
    /// The underlying client that this [`AuthClient`] uses.
    /// pub(crate) dictates that the client is only accessible within the crate.
    pub(crate) client: crate::Client,
}

impl Client {
    /// Convenience method on [`Client`] to access the [`AuthClient`].
    ///
    /// # Example of usage
    ///
    /// ```rust
    /// let client = Client::new(None);
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
            client: self.clone(),
        }
    }
}

/// Break down impl by scope / access
/// I.e., public methods, internal methods, and private methods.
