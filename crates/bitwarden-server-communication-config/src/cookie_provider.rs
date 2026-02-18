/// Trait for providing cookies for a given hostname.
///
/// This trait enables type erasure for cookie provision, allowing middleware
/// to work with any cookie provider implementation without generic parameters.
/// This avoids cascading generic parameters through Client, extension traits,
/// and FFI bindings.
///
/// # Architecture
///
/// Per ADR-006, this trait provides type erasure boundary between middleware
/// and ServerCommunicationConfigClient. The middleware holds `Arc<dyn CookieProvider>`
/// rather than generic `ServerCommunicationConfigClient<R, P>`.
///
/// # Security
///
/// Implementations must NEVER log cookie values. Only hostnames should appear
/// in logs and error messages.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait CookieProvider: Send + Sync {
    /// Retrieves cookies for the given hostname.
    ///
    /// Returns all cookie name/value pairs stored for this hostname, including
    /// sharded cookies (multiple entries with `-N` suffixes for AWS ALB pattern).
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname to retrieve cookies for (e.g., "vault.example.com")
    ///
    /// # Returns
    ///
    /// Vector of cookie name/value tuples. Returns empty vector if no cookies
    /// are stored for the hostname.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let cookies = provider.cookies("api.bitwarden.com".to_string()).await;
    /// // cookies might be: vec![
    /// //   ("AWSELBAuthSessionCookie-0".to_string(), "...".to_string()),
    /// //   ("AWSELBAuthSessionCookie-1".to_string(), "...".to_string()),
    /// // ]
    /// ```
    async fn cookies(&self, hostname: String) -> Vec<(String, String)>;

    /// Acquires cookies for the given hostname from the platform.
    ///
    /// Triggers platform-specific cookie acquisition flow (e.g., browser redirect
    /// to IdP for SSO authentication). The platform opens WebView/browser, user
    /// authenticates, and cookies are retrieved and persisted.
    ///
    /// This method is called by middleware when:
    /// - A redirect response (3xx) is detected indicating cookie requirement
    /// - The hostname needs bootstrap (no cookies currently stored)
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname requiring cookie acquisition (e.g., "vault.example.com")
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Cookie acquisition succeeded and cookies are now available via `cookies()`
    /// - `Err(_)` - Cookie acquisition failed (user cancelled, timeout, platform error, etc.)
    ///
    /// # Security
    ///
    /// Error messages must NOT contain cookie values. Only hostname and error type
    /// should be included in error descriptions.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Middleware detects redirect response
    /// if response.status().is_redirection() {
    ///     let hostname = response.url().host_str().unwrap();
    ///     provider.acquire_cookie(hostname).await?;
    ///     // Cookies now available for retry
    /// }
    /// ```
    async fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
