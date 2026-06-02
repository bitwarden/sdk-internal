//! HTTP client construction shared by all API crates.
//!
//! Centralizing this here ensures the SDK's TLS stack (rustls + platform verifier)
//! is configured identically everywhere a `reqwest::Client` is created. On WASM the
//! browser/Node fetch backend is used and no TLS configuration is applied.

/// Returns a [`reqwest::ClientBuilder`] preconfigured with the SDK's TLS settings.
///
/// On non-WASM targets the builder is wired up with rustls and the platform
/// certificate verifier. On WASM the builder is returned unmodified.
pub fn new_http_client_builder() -> reqwest::ClientBuilder {
    #[allow(unused_mut)]
    let mut client_builder = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        use rustls::ClientConfig;
        use rustls_platform_verifier::ConfigVerifierExt;
        client_builder = client_builder.use_preconfigured_tls(
            ClientConfig::with_platform_verifier().expect("Failed to create platform verifier"),
        );

        // Enforce HTTPS for all requests in non-debug builds
        #[cfg(not(debug_assertions))]
        {
            client_builder = client_builder.https_only(true);
        }
    }

    client_builder
}

/// Returns a [`reqwest::Client`] built from [`new_http_client_builder`].
pub fn new_http_client() -> reqwest::Client {
    new_http_client_builder()
        .build()
        .expect("HTTP client build should not fail")
}
