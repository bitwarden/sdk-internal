/// Provides cookies for injection into outbound HTTP requests.
///
/// # Thread Safety
///
/// Requires `Send + Sync + 'static` for `Arc<dyn CookieProvider>` across thread boundaries.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait CookieProvider: Send + Sync + 'static {
    /// Returns the current cookies for the given hostname.
    /// Returns an empty `Vec` if no cookies are stored or on error.
    async fn cookies(&self, hostname: String) -> Vec<(String, String)>;

    /// Triggers the platform cookie acquisition flow for the given hostname.
    /// Errors are suppressed at the call site (debug! logged) per ADR-006.
    async fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
