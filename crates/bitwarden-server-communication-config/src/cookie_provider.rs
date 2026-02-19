//! Cookie provider trait for middleware integration
//!
//! This module defines the `CookieProvider` trait used by the middleware to retrieve
//! and acquire cookies for HTTP requests. The trait uses type erasure (Arc<dyn CookieProvider>)
//! to avoid generic parameter propagation through the Client and FFI boundaries.

/// Trait for providing cookies to HTTP middleware
///
/// This trait abstracts cookie storage and acquisition, allowing the middleware to
/// inject cookies into requests without depending on concrete storage implementations.
///
/// # Type Erasure
///
/// This trait is designed to be used as `Arc<dyn CookieProvider>` to avoid propagating
/// generic parameters through the Client struct and FFI boundaries. The trait is object-safe
/// (no generic methods, no Self returns) to support dynamic dispatch.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for use in async middleware contexts.
#[async_trait::async_trait]
pub trait CookieProvider: Send + Sync {
    /// Retrieves cookies for the given hostname
    ///
    /// Returns a vector of cookie name-value pairs to be injected into HTTP requests.
    /// For sharded cookies (e.g., AWS ALB), each shard is returned as a separate tuple
    /// with its full name including the `-N` suffix.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.example.com")
    ///
    /// # Returns
    ///
    /// A vector of `(name, value)` tuples. Returns an empty vector if no cookies are stored.
    ///
    /// # Security
    ///
    /// Cookie values are sensitive authentication tokens. Implementations must never log
    /// or expose cookie values in error messages or debug output.
    async fn cookies(&self, hostname: String) -> Vec<(String, String)>;

    /// Acquires cookies for the given hostname from the platform
    ///
    /// Triggers a platform-specific cookie acquisition flow (e.g., opening a WebView
    /// or browser window for the user to authenticate with the identity provider).
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.example.com")
    ///
    /// # Errors
    ///
    /// Returns an error if cookie acquisition fails. The middleware will log the error
    /// but continue gracefully (fail-open for availability).
    ///
    /// # Security
    ///
    /// Cookie values must never appear in error messages. Use generic error descriptions only.
    async fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
