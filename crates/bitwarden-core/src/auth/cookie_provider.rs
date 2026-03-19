/// Provides cookies for injection into outbound HTTP requests.
///
/// # Thread Safety
///
/// Requires `Send + Sync + 'static` for `Arc<dyn CookieProvider>` across thread boundaries.
pub trait CookieProvider: Send + Sync + 'static {
    /// Returns the current cookies for the given hostname.
    /// Returns an empty `Vec` if no cookies are stored or on error.
    fn cookies(
        &self,
        hostname: String,
    ) -> impl std::future::Future<Output = Vec<(String, String)>> + Send + '_;

    /// Triggers the platform cookie acquisition flow for the given hostname.
    /// Errors are suppressed at the call site (debug! logged) per ADR-006.
    fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
           + Send
           + '_;
}
