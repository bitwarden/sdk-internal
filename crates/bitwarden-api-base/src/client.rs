//! HTTP client construction shared by all API crates.
//!
//! Centralizing this here ensures the SDK's TLS stack (rustls + platform verifier)
//! is configured identically everywhere a `reqwest::Client` is created. On WASM the
//! browser/Node fetch backend is used and no TLS configuration is applied.

/// Returns a [`reqwest::ClientBuilder`] preconfigured with the SDK's TLS settings.
///
/// On non-WASM targets the builder is wired up with rustls and the platform
/// certificate verifier. On WASM the builder is returned unmodified.
// TODO Task 4 (PM-38470): add a `client_cert_resolver: Option<Arc<dyn ResolvesClientCert>>`
// parameter here for mTLS. Signature left unchanged in Task 1 to avoid rippling a
// placeholder arg through `new_http_client` and every caller outside bitwarden-core.
pub fn new_http_client_builder() -> reqwest::ClientBuilder {
    #[allow(unused_mut)]
    let mut client_builder = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();

        use rustls::ClientConfig;
        use rustls_platform_verifier::ConfigVerifierExt;
        client_builder = client_builder.tls_backend_preconfigured(
            ClientConfig::with_platform_verifier().expect("Failed to create platform verifier"),
        );

        // Enforce HTTPS for all requests in non-debug builds
        #[cfg(not(debug_assertions))]
        {
            client_builder = client_builder.https_only(true);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::Duration;
        const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
        const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
        client_builder = client_builder
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .read_timeout(DEFAULT_READ_TIMEOUT);
    }

    client_builder
}

/// Returns a [`reqwest::Client`] built from [`new_http_client_builder`].
pub fn new_http_client() -> reqwest::Client {
    new_http_client_builder()
        .build()
        .expect("HTTP client build should not fail")
}
