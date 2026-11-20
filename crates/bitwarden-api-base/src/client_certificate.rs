//! TLS client certificates (mTLS) whose private key stays with the host application.
//!
//! The application supplies the certificate chain and a [`ClientCertSigner`] that signs the TLS
//! handshake with a key held in the platform keystore. Only the chain and the signatures cross the
//! FFI boundary.

use std::sync::Arc;

use rustls::{
    SignatureAlgorithm, SignatureScheme,
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
};

/// A TLS signature scheme a client certificate key can sign with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TlsSigScheme {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256, MGF1 with SHA-256, and a 32-byte salt.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384, MGF1 with SHA-384, and a 48-byte salt.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512, MGF1 with SHA-512, and a 64-byte salt.
    RsaPssSha512,
    /// ECDSA on P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
}

/// The SDK's preference order, strongest first. The RSA order matches rustls' own RSA keys.
const SCHEME_PREFERENCE: [TlsSigScheme; 8] = [
    TlsSigScheme::EcdsaP384Sha384,
    TlsSigScheme::EcdsaP256Sha256,
    TlsSigScheme::RsaPssSha512,
    TlsSigScheme::RsaPssSha384,
    TlsSigScheme::RsaPssSha256,
    TlsSigScheme::RsaPkcs1Sha512,
    TlsSigScheme::RsaPkcs1Sha384,
    TlsSigScheme::RsaPkcs1Sha256,
];

impl TlsSigScheme {
    fn to_rustls(self) -> SignatureScheme {
        match self {
            Self::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
            Self::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
            Self::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
            Self::RsaPssSha256 => SignatureScheme::RSA_PSS_SHA256,
            Self::RsaPssSha384 => SignatureScheme::RSA_PSS_SHA384,
            Self::RsaPssSha512 => SignatureScheme::RSA_PSS_SHA512,
            Self::EcdsaP256Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::EcdsaP384Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        }
    }

    fn algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::RSA,
        }
    }
}

/// Error returned by a [`ClientCertSigner`].
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ClientCertSignerError {
    /// The platform could not produce the signature.
    #[error("Client certificate signing failed: {reason}")]
    SigningFailed {
        /// Description of the failure. It reaches the SDK logs, so it must not contain secrets.
        reason: String,
    },
    /// The foreign implementation raised an error it did not declare.
    #[error("Unexpected client certificate signer error: {reason}")]
    Unexpected {
        /// Description of the failure.
        reason: String,
    },
}

#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for ClientCertSignerError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected { reason: e.reason }
    }
}

/// Signs TLS handshakes with the private key of a client certificate, which never leaves the
/// host application.
///
/// Both methods are called synchronously on the caller's thread: `schemes` inside
/// [`ClientCertificate::new`], and `sign` during the TLS handshake, on the thread that awaits the
/// networked SDK call. Apps must not await networked SDK calls on the main thread, and
/// implementations must be thread-safe and must not block on user interaction.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait ClientCertSigner: Send + Sync {
    /// Signs `message` with `scheme`, which is always one of the schemes returned by
    /// [`schemes`](Self::schemes).
    ///
    /// `message` is the raw data to sign, not a digest: hash it with the scheme's hash as part of
    /// signing. The result must be an ASN.1 DER `ECDSA-Sig-Value` for ECDSA, an RSASSA-PKCS1-v1_5
    /// signature for the PKCS#1 schemes, and an RSASSA-PSS signature with MGF1 over the same hash
    /// and a salt as long as the digest for the PSS schemes.
    fn sign(
        &self,
        scheme: TlsSigScheme,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, ClientCertSignerError>;

    /// Every scheme the key can sign with. The SDK calls this once, when the certificate is
    /// configured, and picks its preferred scheme among those the server accepts.
    fn schemes(&self) -> Vec<TlsSigScheme>;
}

/// A client certificate chain and the signer for its private key.
///
/// It is presented to every host that requests client authentication on a connection the client
/// opens. That includes an `https://` proxy and the target of a cross-host redirect, which is
/// still followed.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClientCertificate {
    resolver: Arc<DelegatedResolver>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ClientCertificate {
    /// Creates a client certificate from its DER-encoded chain, leaf first, followed by any
    /// intermediates, and the signer for the leaf's private key.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(chain: Vec<Vec<u8>>, signer: Arc<dyn ClientCertSigner>) -> Self {
        let mut schemes = signer.schemes();
        schemes.sort_by_key(|scheme| SCHEME_PREFERENCE.iter().position(|s| s == scheme));
        schemes.dedup();

        if schemes.is_empty() {
            tracing::error!(
                "mTLS: the client certificate signer advertised no signature schemes, so the \
                 client certificate will never be sent"
            );
        } else if schemes
            .iter()
            .any(|scheme| scheme.algorithm() != schemes[0].algorithm())
        {
            tracing::error!(
                ?schemes,
                "mTLS: the client certificate signer advertised schemes for more than one key type"
            );
        }

        let key = Arc::new(DelegatedSigningKey { signer, schemes });
        let certified_key =
            CertifiedKey::new(chain.into_iter().map(CertificateDer::from).collect(), key);
        Self {
            resolver: Arc::new(DelegatedResolver {
                certified_key: Arc::new(certified_key),
            }),
        }
    }
}

impl ClientCertificate {
    pub(crate) fn resolver(&self) -> Arc<dyn ResolvesClientCert> {
        self.resolver.clone()
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate").finish_non_exhaustive()
    }
}

/// Ignores the server's acceptable-issuer hints, since there is only one certificate to offer.
#[derive(Debug)]
struct DelegatedResolver {
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesClientCert for DelegatedResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct DelegatedSigningKey {
    signer: Arc<dyn ClientCertSigner>,
    /// The signer's schemes in the SDK's preference order.
    schemes: Vec<TlsSigScheme>,
}

impl std::fmt::Debug for DelegatedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedSigningKey")
            .field("schemes", &self.schemes)
            .finish_non_exhaustive()
    }
}

impl SigningKey for DelegatedSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let chosen = self
            .schemes
            .iter()
            .copied()
            .find(|scheme| offered.contains(&scheme.to_rustls()));
        match chosen {
            Some(scheme) => Some(Box::new(DelegatedSigner {
                signer: self.signer.clone(),
                scheme,
            })),
            None => {
                // The handshake continues without a certificate, and the server's rejection would
                // otherwise be unexplained.
                tracing::warn!(
                    ours = ?self.schemes,
                    server = ?offered,
                    "mTLS: the server accepts none of the client certificate's signature \
                     schemes, so no client certificate is sent"
                );
                None
            }
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.schemes
            .first()
            .map_or(SignatureAlgorithm::Anonymous, |scheme| scheme.algorithm())
    }
}

struct DelegatedSigner {
    signer: Arc<dyn ClientCertSigner>,
    scheme: TlsSigScheme,
}

impl std::fmt::Debug for DelegatedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for DelegatedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.signer
            .sign(self.scheme, message.to_vec())
            .map_err(|error| {
                tracing::error!(scheme = ?self.scheme, "mTLS: {error}");
                rustls::Error::General(error.to_string())
            })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme.to_rustls()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingSigner {
        schemes: Vec<TlsSigScheme>,
        fail: bool,
        calls: Mutex<Vec<(TlsSigScheme, Vec<u8>)>>,
    }

    impl ClientCertSigner for RecordingSigner {
        fn sign(
            &self,
            scheme: TlsSigScheme,
            message: Vec<u8>,
        ) -> Result<Vec<u8>, ClientCertSignerError> {
            self.calls
                .lock()
                .expect("lock should not be poisoned")
                .push((scheme, message));
            if self.fail {
                Err(ClientCertSignerError::SigningFailed {
                    reason: "key unavailable".to_owned(),
                })
            } else {
                Ok(b"signature".to_vec())
            }
        }

        fn schemes(&self) -> Vec<TlsSigScheme> {
            self.schemes.clone()
        }
    }

    fn signing_key(signer: &Arc<RecordingSigner>) -> Arc<dyn SigningKey> {
        let certificate = ClientCertificate::new(vec![b"leaf".to_vec()], signer.clone());
        let certified_key = certificate
            .resolver()
            .resolve(&[], &[])
            .expect("resolver should always offer the certificate");
        assert_eq!(
            certified_key.cert,
            vec![CertificateDer::from(b"leaf".to_vec())]
        );
        certified_key.key.clone()
    }

    const ALL_RSA: [TlsSigScheme; 6] = [
        TlsSigScheme::RsaPkcs1Sha256,
        TlsSigScheme::RsaPkcs1Sha384,
        TlsSigScheme::RsaPkcs1Sha512,
        TlsSigScheme::RsaPssSha256,
        TlsSigScheme::RsaPssSha384,
        TlsSigScheme::RsaPssSha512,
    ];

    #[test]
    fn chooses_the_sdk_preferred_scheme_among_those_offered() {
        let signer = Arc::new(RecordingSigner {
            schemes: ALL_RSA.to_vec(),
            ..Default::default()
        });
        let key = signing_key(&signer);

        let offered = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
        ];
        let chosen = key.choose_scheme(&offered).expect("a scheme should match");

        assert_eq!(chosen.scheme(), SignatureScheme::RSA_PSS_SHA384);
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
    }

    #[test]
    fn falls_back_to_pkcs1_when_the_server_offers_no_pss() {
        let signer = Arc::new(RecordingSigner {
            schemes: ALL_RSA.to_vec(),
            ..Default::default()
        });
        let key = signing_key(&signer);

        let chosen = key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ED25519])
            .expect("a scheme should match");

        assert_eq!(chosen.scheme(), SignatureScheme::RSA_PKCS1_SHA256);
    }

    #[test]
    fn returns_none_when_no_scheme_is_shared() {
        let signer = Arc::new(RecordingSigner {
            schemes: vec![TlsSigScheme::EcdsaP256Sha256],
            ..Default::default()
        });
        let key = signing_key(&signer);

        assert!(
            key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);
    }

    #[test]
    fn empty_schemes_never_match() {
        let signer = Arc::new(RecordingSigner::default());
        let key = signing_key(&signer);

        assert!(
            key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        assert_eq!(key.algorithm(), SignatureAlgorithm::Anonymous);
    }

    #[test]
    fn signer_receives_the_negotiated_scheme_and_the_raw_message() {
        let signer = Arc::new(RecordingSigner {
            schemes: vec![TlsSigScheme::EcdsaP256Sha256],
            ..Default::default()
        });
        let key = signing_key(&signer);
        let chosen = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("a scheme should match");

        let signature = chosen.sign(b"handshake").expect("signing should succeed");

        assert_eq!(signature, b"signature");
        assert_eq!(
            *signer.calls.lock().expect("lock should not be poisoned"),
            vec![(TlsSigScheme::EcdsaP256Sha256, b"handshake".to_vec())]
        );
    }

    #[test]
    fn signer_errors_become_rustls_errors() {
        let signer = Arc::new(RecordingSigner {
            schemes: vec![TlsSigScheme::EcdsaP256Sha256],
            fail: true,
            ..Default::default()
        });
        let key = signing_key(&signer);
        let chosen = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("a scheme should match");

        let error = chosen.sign(b"handshake").expect_err("signing should fail");

        assert_eq!(
            error,
            rustls::Error::General("Client certificate signing failed: key unavailable".to_owned())
        );
    }
}
