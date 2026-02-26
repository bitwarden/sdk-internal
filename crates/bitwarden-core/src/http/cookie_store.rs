use super::{Cookie, CookieError};

/// Abstraction for cookie storage backends.
///
/// Enables multiple implementations (in-memory, file system, platform secure storage)
/// without coupling middleware to specific storage mechanisms. Uses async methods to
/// support I/O-bound operations.
///
/// See ADR-047 for rationale on using async-trait for dynamic dispatch.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait CookieStore: Send + Sync {
    /// Retrieves a cookie by name.
    ///
    /// Returns None if cookie not found or expired (implementations should check expiration).
    async fn get_cookie(&self, name: &str) -> Result<Option<Cookie>, CookieError>;

    /// Stores a cookie with security attribute validation.
    ///
    /// Implementations should call cookie.validate_security_attributes() before persisting.
    async fn set_cookie(&self, cookie: Cookie) -> Result<(), CookieError>;

    /// Removes a cookie by name.
    ///
    /// Returns Ok even if cookie doesn't exist (idempotent operation).
    async fn remove_cookie(&self, name: &str) -> Result<(), CookieError>;

    /// Clears all stored cookies.
    async fn clear(&self) -> Result<(), CookieError>;

    /// Lists all non-expired cookie names (for debugging/testing).
    async fn list_cookies(&self) -> Result<Vec<String>, CookieError>;
}
