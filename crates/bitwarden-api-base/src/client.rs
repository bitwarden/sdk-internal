//! HTTP client construction shared by all API crates.
//!
//! Centralizing this here ensures the SDK's TLS stack (rustls + platform verifier)
//! is configured identically everywhere a `reqwest::Client` is created. On WASM the
//! browser/Node fetch backend is used and no TLS configuration is applied.

/// Error returned by a foreign [`ClientCertSigner`] implementation.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, thiserror::Error)]
pub enum ClientCertSignerError {
    /// The foreign signer failed to produce a signature.
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for ClientCertSignerError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ClientCertSignerError::SigningFailed(e.reason)
    }
}

/// TLS signature schemes a client certificate can be used with.
///
/// Mirrors the subset of [`rustls::SignatureScheme`] exposed across the FFI boundary.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSigScheme {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512.
    RsaPssSha512,
    /// ECDSA over NIST P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA over NIST P-384 with SHA-384.
    EcdsaP384Sha384,
    // Ed25519 deliberately omitted: deferred (no kSecAttrKeyType constant on Apple for it)
}

#[cfg(not(target_arch = "wasm32"))]
impl From<TlsSigScheme> for rustls::SignatureScheme {
    fn from(s: TlsSigScheme) -> Self {
        match s {
            TlsSigScheme::RsaPkcs1Sha256 => rustls::SignatureScheme::RSA_PKCS1_SHA256,
            TlsSigScheme::RsaPkcs1Sha384 => rustls::SignatureScheme::RSA_PKCS1_SHA384,
            TlsSigScheme::RsaPkcs1Sha512 => rustls::SignatureScheme::RSA_PKCS1_SHA512,
            TlsSigScheme::RsaPssSha256 => rustls::SignatureScheme::RSA_PSS_SHA256,
            TlsSigScheme::RsaPssSha384 => rustls::SignatureScheme::RSA_PSS_SHA384,
            TlsSigScheme::RsaPssSha512 => rustls::SignatureScheme::RSA_PSS_SHA512,
            TlsSigScheme::EcdsaP256Sha256 => rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            TlsSigScheme::EcdsaP384Sha384 => rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        }
    }
}

/// Foreign-implemented signer for mTLS client authentication.
///
/// The private key never crosses the FFI boundary; the host platform performs the
/// signing operation (e.g. via the Apple Secure Enclave / Keychain or Android KeyStore).
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait ClientCertSigner: std::fmt::Debug + Send + Sync {
    /// Signs `message` with the client's private key, returning the raw signature.
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, ClientCertSignerError>;
    /// Returns the signature schemes the client key supports, in preference order.
    fn schemes(&self) -> Vec<TlsSigScheme>;
    // algorithm() is NOT part of the FFI surface; Rust derives it from schemes()
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct DelegatedResolver {
    certified: std::sync::Arc<rustls::sign::CertifiedKey>,
}

#[cfg(not(target_arch = "wasm32"))]
impl rustls::client::ResolvesClientCert for DelegatedResolver {
    fn resolve(
        &self,
        _hints: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct DelegatedSigningKey {
    app: std::sync::Arc<dyn ClientCertSigner>,
    schemes: Vec<TlsSigScheme>,
}

#[cfg(not(target_arch = "wasm32"))]
impl rustls::sign::SigningKey for DelegatedSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        let mine: Vec<rustls::SignatureScheme> =
            self.schemes.iter().copied().map(Into::into).collect();
        match mine.iter().find(|s| offered.contains(s)).copied() {
            Some(scheme) => Some(Box::new(DelegatedSigner {
                app: self.app.clone(),
                scheme,
            })),
            None => {
                tracing::error!(
                    "mTLS: no shared signature scheme. ours={mine:?} server={offered:?}"
                );
                None
            }
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        match self.schemes.first() {
            Some(
                TlsSigScheme::RsaPkcs1Sha256
                | TlsSigScheme::RsaPkcs1Sha384
                | TlsSigScheme::RsaPkcs1Sha512
                | TlsSigScheme::RsaPssSha256
                | TlsSigScheme::RsaPssSha384
                | TlsSigScheme::RsaPssSha512,
            ) => rustls::SignatureAlgorithm::RSA,
            Some(TlsSigScheme::EcdsaP256Sha256 | TlsSigScheme::EcdsaP384Sha384) => {
                rustls::SignatureAlgorithm::ECDSA
            }
            None => rustls::SignatureAlgorithm::Anonymous,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct DelegatedSigner {
    app: std::sync::Arc<dyn ClientCertSigner>,
    scheme: rustls::SignatureScheme,
}

#[cfg(not(target_arch = "wasm32"))]
impl rustls::sign::Signer for DelegatedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.app
            .sign(message.to_vec())
            .map_err(|e| rustls::Error::General(e.to_string()))
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

/// Builds a rustls client-certificate resolver that delegates signing to a foreign
/// [`ClientCertSigner`].
///
/// `chain` is the DER-encoded certificate chain (leaf first). The resolver always
/// presents this chain when the server requests client authentication.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_client_cert_resolver(
    chain: Vec<Vec<u8>>,
    signer: std::sync::Arc<dyn ClientCertSigner>,
) -> std::sync::Arc<dyn rustls::client::ResolvesClientCert> {
    use rustls::{
        pki_types::CertificateDer,
        sign::{CertifiedKey, SigningKey},
    };

    let schemes = signer.schemes();
    if schemes.is_empty() {
        tracing::error!(
            "mTLS: signer advertised no signature schemes; client auth will not be sent"
        );
    }
    let key: std::sync::Arc<dyn SigningKey> = std::sync::Arc::new(DelegatedSigningKey {
        app: signer,
        schemes,
    });
    let cert_chain: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    std::sync::Arc::new(DelegatedResolver {
        certified: std::sync::Arc::new(CertifiedKey {
            cert: cert_chain,
            key,
            ocsp: None,
        }),
    })
}

/// Returns a [`reqwest::ClientBuilder`] preconfigured with the SDK's TLS settings.
///
/// On non-WASM targets the builder is wired up with rustls and the platform
/// certificate verifier. When `client_cert_resolver` is `Some`, the resulting TLS
/// config also presents a client certificate for mTLS. On WASM the builder is
/// returned unmodified.
pub fn new_http_client_builder(
    #[cfg(not(target_arch = "wasm32"))] client_cert_resolver: Option<
        std::sync::Arc<dyn rustls::client::ResolvesClientCert>,
    >,
) -> reqwest::ClientBuilder {
    #[allow(unused_mut)]
    let mut client_builder = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();

        use rustls::ClientConfig;
        use rustls_platform_verifier::{BuilderVerifierExt, ConfigVerifierExt};

        // When a client-cert resolver is provided, chain through the builder so the
        // resolver is attached before the config is finalized; otherwise use the
        // no-client-auth form.
        let tls_config = match client_cert_resolver {
            Some(resolver) => ClientConfig::builder()
                .with_platform_verifier()
                .expect("Failed to create platform verifier")
                .with_client_cert_resolver(resolver),
            None => {
                ClientConfig::with_platform_verifier().expect("Failed to create platform verifier")
            }
        };
        client_builder = client_builder.tls_backend_preconfigured(tls_config);

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
    new_http_client_builder(
        #[cfg(not(target_arch = "wasm32"))]
        None,
    )
    .build()
    .expect("HTTP client build should not fail")
}
