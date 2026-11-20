//! HTTP client construction shared by all API crates.
//!
//! Centralizing this here ensures the SDK's TLS stack (rustls + platform verifier)
//! is configured identically everywhere a `reqwest::Client` is created. On WASM the
//! browser/Node fetch backend is used and no TLS configuration is applied.

/// Covers the TCP connection, any proxy tunnel, and the TLS handshake.
#[cfg(not(target_arch = "wasm32"))]
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long an HTTP/2 connection with requests in flight may receive nothing before it is pinged.
/// An alive peer answers the ping, so a slow transfer is never cut off.
#[cfg(not(target_arch = "wasm32"))]
const HTTP2_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for the ping acknowledgement before closing the connection as dead.
#[cfg(not(target_arch = "wasm32"))]
const HTTP2_KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Idle time before the first TCP keep-alive probe, to detect dead peers on HTTP/1.1.
#[cfg(not(target_arch = "wasm32"))]
const TCP_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Time between unanswered TCP keep-alive probes.
#[cfg(not(target_arch = "wasm32"))]
const TCP_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Unanswered probes before the kernel closes the connection: 30s + 3 x 10s for an idle peer.
#[cfg(not(target_arch = "wasm32"))]
const TCP_KEEPALIVE_RETRIES: u32 = 3;

/// How long sent data may stay unacknowledged before the kernel closes the connection. Keep-alive
/// probes only run on an idle socket, so this covers a peer that vanishes mid-upload.
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const TCP_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Returns a [`reqwest::ClientBuilder`] with the SDK's TLS, connect timeout, and keep-alive
/// defaults. On WASM the builder is returned unmodified.
pub fn new_http_client_builder() -> reqwest::ClientBuilder {
    #[cfg(not(target_arch = "wasm32"))]
    {
        native::builder(native::platform_verifier().with_no_client_auth())
    }

    #[cfg(target_arch = "wasm32")]
    {
        reqwest::Client::builder()
    }
}

/// Returns a builder like [`new_http_client_builder`] that also presents `client_certificate`.
/// Only use it for clients that talk to Bitwarden servers.
#[cfg(not(target_arch = "wasm32"))]
pub fn new_http_client_builder_with_client_certificate(
    client_certificate: &crate::ClientCertificate,
) -> reqwest::ClientBuilder {
    native::builder(
        native::platform_verifier().with_client_cert_resolver(client_certificate.resolver()),
    )
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use rustls::{ClientConfig, ConfigBuilder, client::WantsClientCert};
    use rustls_platform_verifier::BuilderVerifierExt;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    use super::TCP_USER_TIMEOUT;
    use super::{
        CONNECT_TIMEOUT, HTTP2_KEEP_ALIVE_INTERVAL, HTTP2_KEEP_ALIVE_TIMEOUT, TCP_KEEPALIVE,
        TCP_KEEPALIVE_INTERVAL, TCP_KEEPALIVE_RETRIES,
    };

    pub(super) fn platform_verifier() -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        ClientConfig::builder()
            .with_platform_verifier()
            .expect("Failed to create platform verifier")
    }

    pub(super) fn builder(mut tls: ClientConfig) -> reqwest::ClientBuilder {
        // The HTTP/2 pings need h2, which reqwest does not offer on a preconfigured rustls config.
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        // No default read timeout, since it is not reset while the request body uploads and would
        // fail slow uploads.
        #[allow(unused_mut)]
        let mut client_builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
            .http2_keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(false)
            .tcp_keepalive(TCP_KEEPALIVE)
            .tcp_keepalive_interval(TCP_KEEPALIVE_INTERVAL)
            .tcp_keepalive_retries(TCP_KEEPALIVE_RETRIES);

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            client_builder = client_builder.tcp_user_timeout(TCP_USER_TIMEOUT);
        }

        // Enforce HTTPS for all requests in non-debug builds
        #[cfg(not(debug_assertions))]
        {
            client_builder = client_builder.https_only(true);
        }

        client_builder
    }
}

/// Returns a [`reqwest::Client`] built from [`new_http_client_builder`].
pub fn new_http_client() -> reqwest::Client {
    new_http_client_builder()
        .build()
        .expect("HTTP client build should not fail")
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn builder_applies_default_connect_timeout_only() {
        let builder_debug = format!("{:?}", new_http_client_builder());
        let client_debug = format!("{:?}", new_http_client());

        assert!(
            builder_debug.contains("connect_timeout: 30s"),
            "{builder_debug}"
        );
        assert!(!client_debug.contains("read_timeout"), "{client_debug}");
        assert!(!client_debug.contains("TotalTimeout"), "{client_debug}");
    }
}
