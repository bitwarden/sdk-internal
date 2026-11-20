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

    /// Whether an RSA key with a modulus of `modulus_bits` can encode this scheme's signature, per
    /// RFC 8017 sections 9.1.1 (PSS with a digest-length salt) and 9.2 (PKCS #1 v1.5, whose
    /// SHA-2 `DigestInfo` prefix is 19 bytes).
    fn fits_rsa_modulus(self, modulus_bits: usize) -> bool {
        let (digest_len, pss) = match self {
            Self::RsaPkcs1Sha256 => (32, false),
            Self::RsaPkcs1Sha384 => (48, false),
            Self::RsaPkcs1Sha512 => (64, false),
            Self::RsaPssSha256 => (32, true),
            Self::RsaPssSha384 => (48, true),
            Self::RsaPssSha512 => (64, true),
            Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384 => return false,
        };
        if pss {
            modulus_bits.saturating_sub(1).div_ceil(8) >= 2 * digest_len + 2
        } else {
            modulus_bits.div_ceil(8) >= 19 + digest_len + 11
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
/// [`ClientCertificate::new`], and `sign` inside [`ClientCertificate::validate`] and during the TLS
/// handshake, on the thread that awaits the networked SDK call. Apps must not await networked SDK
/// calls on the main thread, and implementations must be thread-safe and must not block on user
/// interaction.
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

    /// Every scheme the key can sign with. The SDK calls this once, keeps those that fit the leaf's
    /// key, and picks its preferred one among those the server accepts.
    fn schemes(&self) -> Vec<TlsSigScheme>;
}

/// A client certificate chain and the signer for its private key.
///
/// It is presented to every host that requests client authentication on a connection the client
/// opens. That includes an `https://` proxy and the target of a cross-host redirect, which is
/// still followed.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClientCertificate {
    key: Arc<DelegatedSigningKey>,
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
        let chain: Vec<CertificateDer<'static>> =
            chain.into_iter().map(CertificateDer::from).collect();
        // An unparseable leaf keeps every scheme, and `validate` reports it.
        if let Some(key_type) = chain.first().and_then(leaf_key_type) {
            schemes.retain(|scheme| key_type.accepts(*scheme));
        }

        if schemes.is_empty() {
            tracing::error!(
                "mTLS: the client certificate signer advertised no signature schemes for the \
                 leaf's key, so the client certificate will never be sent"
            );
        }

        let key = Arc::new(DelegatedSigningKey { signer, schemes });
        let certified_key = CertifiedKey::new(chain, key.clone());
        Self {
            key,
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

    /// Checks that the chain parses and that the signer's signature with every scheme it advertises
    /// for the leaf's key verifies against that key.
    pub fn validate(&self) -> Result<(), ClientCertificateError> {
        let certificates = self
            .resolver
            .certified_key
            .cert
            .iter()
            .enumerate()
            .map(|(index, certificate)| {
                webpki::EndEntityCert::try_from(certificate)
                    .map_err(|_| ClientCertificateError::InvalidCertificate { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = certificates
            .first()
            .ok_or(ClientCertificateError::EmptyChain)?;
        let key_type = LeafKeyType::from_spki(leaf.subject_public_key_info().as_ref())
            .ok_or(ClientCertificateError::UnsupportedKey)?;
        if self.key.schemes.is_empty() {
            return Err(ClientCertificateError::NoCompatibleScheme);
        }
        for &scheme in &self.key.schemes {
            let signature = self
                .key
                .signer
                .sign(scheme, PROBE_MESSAGE.to_vec())
                .map_err(|error| ClientCertificateError::SigningFailed {
                    scheme,
                    reason: error.to_string(),
                })?;
            if key_type.is_verifiable() && !verifies(leaf, scheme, &signature) {
                return Err(ClientCertificateError::KeyMismatch { scheme });
            }
        }
        Ok(())
    }
}

/// Not a TLS handshake message, so a signature over it cannot stand in for one.
const PROBE_MESSAGE: &[u8] = b"Bitwarden SDK client certificate check";

fn verifies(leaf: &webpki::EndEntityCert<'_>, scheme: TlsSigScheme, signature: &[u8]) -> bool {
    crate::client::crypto_provider()
        .signature_verification_algorithms
        .mapping
        .iter()
        .filter(|(mapped, _)| *mapped == scheme.to_rustls())
        .flat_map(|(_, algorithms)| algorithms.iter())
        .any(|algorithm| {
            leaf.verify_signature(*algorithm, PROBE_MESSAGE, signature)
                .is_ok()
        })
}

fn leaf_key_type(leaf: &CertificateDer<'_>) -> Option<LeafKeyType> {
    let leaf = webpki::EndEntityCert::try_from(leaf).ok()?;
    LeafKeyType::from_spki(leaf.subject_public_key_info().as_ref())
}

/// Why [`ClientCertificate::validate`] rejected a certificate.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClientCertificateError {
    /// The chain contains no certificates.
    #[error("The certificate chain is empty")]
    EmptyChain,
    /// A certificate in the chain is not valid X.509 DER.
    #[error("Certificate {index} in the chain is not a valid X.509 certificate")]
    InvalidCertificate {
        /// Position in the chain, where 0 is the leaf.
        index: usize,
    },
    /// The leaf's key is neither RSA nor ECDSA on P-256 or P-384.
    #[error("The leaf certificate's key is not RSA or ECDSA on P-256 or P-384")]
    UnsupportedKey,
    /// The signer advertises no scheme that matches the leaf's key.
    #[error("The signer advertises no signature scheme for the leaf certificate's key")]
    NoCompatibleScheme,
    /// The signer failed to sign the test message.
    #[error("The signer failed to sign with {scheme:?}: {reason}")]
    SigningFailed {
        /// The scheme the signature was requested with.
        scheme: TlsSigScheme,
        /// The signer's error.
        reason: String,
    },
    /// The signer's signature does not verify with the leaf certificate's key.
    #[error("The {scheme:?} signature does not match the leaf certificate's key")]
    KeyMismatch {
        /// The scheme the signature was made with.
        scheme: TlsSigScheme,
    },
}

/// The leaf key types the SDK can sign handshakes for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeafKeyType {
    Rsa { modulus_bits: usize },
    EcdsaP256,
    EcdsaP384,
}

impl LeafKeyType {
    /// Reads the key type from the DER `AlgorithmIdentifier` at the start of an SPKI. DER encodes
    /// each identifier as a single byte string, so comparing prefixes is exact.
    fn from_spki(spki: &[u8]) -> Option<Self> {
        // rsaEncryption, with or without the NULL parameters.
        const RSA: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        // id-ecPublicKey followed by the named curve.
        const EC_P256: &[u8] = &[
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        const EC_P384: &[u8] = &[
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
            0x00, 0x22,
        ];

        let (content, _) = der_expect(spki, DER_SEQUENCE)?;
        let (algorithm, rest) = der_expect(content, DER_SEQUENCE)?;
        if algorithm.starts_with(RSA) {
            let (public_key, _) = der_expect(rest, DER_BIT_STRING)?;
            // The first byte counts the unused bits, which is 0 for every key encoding.
            let modulus_bits = rsa_modulus_bits(public_key.strip_prefix(&[0])?)?;
            Some(Self::Rsa { modulus_bits })
        } else if algorithm == EC_P256 {
            Some(Self::EcdsaP256)
        } else if algorithm == EC_P384 {
            Some(Self::EcdsaP384)
        } else {
            None
        }
    }

    fn accepts(self, scheme: TlsSigScheme) -> bool {
        match self {
            Self::Rsa { modulus_bits } => scheme.fits_rsa_modulus(modulus_bits),
            Self::EcdsaP256 => scheme == TlsSigScheme::EcdsaP256Sha256,
            Self::EcdsaP384 => scheme == TlsSigScheme::EcdsaP384Sha384,
        }
    }

    /// RSA keys outside 2048 to 8192 bits are only checked for a successful signature, since the
    /// rustls providers reject them.
    fn is_verifiable(self) -> bool {
        match self {
            Self::Rsa { modulus_bits } => (2048..=8192).contains(&modulus_bits),
            Self::EcdsaP256 | Self::EcdsaP384 => true,
        }
    }
}

const DER_INTEGER: u8 = 0x02;
const DER_BIT_STRING: u8 = 0x03;
const DER_SEQUENCE: u8 = 0x30;

/// Returns the bit length of the modulus of a DER `RSAPublicKey`.
fn rsa_modulus_bits(public_key: &[u8]) -> Option<usize> {
    let (key, _) = der_expect(public_key, DER_SEQUENCE)?;
    let (modulus, _) = der_expect(key, DER_INTEGER)?;
    let start = modulus.iter().position(|&byte| byte != 0)?;
    let significant = &modulus[start..];
    Some(significant.len() * 8 - significant[0].leading_zeros() as usize)
}

/// Splits the DER element at the start of `der` into its content and the bytes after it, if its
/// tag is `tag`.
fn der_expect(der: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&actual, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    if actual != tag {
        return None;
    }
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        let len = bytes
            .iter()
            .fold(0usize, |len, &byte| (len << 8) | usize::from(byte));
        (len, rest)
    };
    (len <= rest.len()).then(|| rest.split_at(len))
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

    #[test]
    fn rsa_schemes_fit_the_modulus_rfc_8017_requires() {
        let fitting = |modulus_bits| {
            ALL_RSA
                .into_iter()
                .filter(|scheme| scheme.fits_rsa_modulus(modulus_bits))
                .collect::<Vec<_>>()
        };

        assert_eq!(fitting(2048), ALL_RSA);
        assert_eq!(fitting(1034), ALL_RSA);
        // PSS with SHA-512 needs a 130-byte encoded message, and a 1033-bit key encodes 129.
        assert_eq!(
            fitting(1033),
            ALL_RSA
                .into_iter()
                .filter(|scheme| *scheme != TlsSigScheme::RsaPssSha512)
                .collect::<Vec<_>>()
        );
        assert_eq!(fitting(512), vec![TlsSigScheme::RsaPkcs1Sha256]);
        assert!(!TlsSigScheme::EcdsaP256Sha256.fits_rsa_modulus(4096));
    }

    #[test]
    fn reads_the_rsa_modulus_length_without_the_sign_byte() {
        // SEQUENCE { INTEGER 0x00 0x80 0x00 0x01, INTEGER 65537 }: a 24-bit modulus.
        let key = [
            0x30, 0x0b, 0x02, 0x04, 0x00, 0x80, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        assert_eq!(rsa_modulus_bits(&key), Some(24));

        // SEQUENCE { INTEGER 0x01 0xff, ... }: the top byte has 7 leading zero bits.
        let key = [
            0x30, 0x09, 0x02, 0x02, 0x01, 0xff, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        assert_eq!(rsa_modulus_bits(&key), Some(9));

        assert_eq!(rsa_modulus_bits(&[0x30, 0x03, 0x02, 0x01, 0x00]), None);
    }

    const P256_CERT: &str = include_str!("../tests/fixtures/client_certificate/p256.crt");
    const P256_KEY: &str = include_str!("../tests/fixtures/client_certificate/p256.key");
    const P256_OTHER_KEY: &str =
        include_str!("../tests/fixtures/client_certificate/p256-other.key");
    const P384_CERT: &str = include_str!("../tests/fixtures/client_certificate/p384.crt");
    const P384_KEY: &str = include_str!("../tests/fixtures/client_certificate/p384.key");
    const RSA_CERT: &str = include_str!("../tests/fixtures/client_certificate/rsa.crt");
    const RSA_KEY: &str = include_str!("../tests/fixtures/client_certificate/rsa.key");
    const ED25519_CERT: &str = include_str!("../tests/fixtures/client_certificate/ed25519.crt");

    fn der(pem: &str) -> Vec<u8> {
        use rustls::pki_types::pem::PemObject;

        CertificateDer::from_pem_slice(pem.as_bytes())
            .expect("fixture should be a PEM certificate")
            .to_vec()
    }

    /// Advertises `schemes` and signs each of them with `key`.
    struct KeySigner {
        key: Arc<dyn SigningKey>,
        schemes: Vec<TlsSigScheme>,
    }

    impl KeySigner {
        fn new(key_pem: &str, schemes: &[TlsSigScheme]) -> Arc<Self> {
            use rustls::pki_types::{PrivateKeyDer, pem::PemObject};

            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .expect("fixture should be a PEM private key");
            Arc::new(Self {
                key: crate::client::crypto_provider()
                    .key_provider
                    .load_private_key(key)
                    .expect("fixture key should load"),
                schemes: schemes.to_vec(),
            })
        }
    }

    impl ClientCertSigner for KeySigner {
        fn sign(
            &self,
            scheme: TlsSigScheme,
            message: Vec<u8>,
        ) -> Result<Vec<u8>, ClientCertSignerError> {
            let signer = self
                .key
                .choose_scheme(&[scheme.to_rustls()])
                .expect("fixture key should support the scheme");
            Ok(signer.sign(&message).expect("signing should succeed"))
        }

        fn schemes(&self) -> Vec<TlsSigScheme> {
            self.schemes.clone()
        }
    }

    fn validate(
        chain: Vec<Vec<u8>>,
        signer: Arc<dyn ClientCertSigner>,
    ) -> Result<(), ClientCertificateError> {
        ClientCertificate::new(chain, signer).validate()
    }

    fn unusable_signer(schemes: &[TlsSigScheme]) -> Arc<RecordingSigner> {
        Arc::new(RecordingSigner {
            schemes: schemes.to_vec(),
            fail: true,
            ..Default::default()
        })
    }

    #[test]
    fn validate_accepts_keys_that_sign_every_advertised_scheme() {
        validate(
            vec![der(P256_CERT)],
            KeySigner::new(P256_KEY, &[TlsSigScheme::EcdsaP256Sha256]),
        )
        .unwrap();
        validate(
            vec![der(P384_CERT)],
            KeySigner::new(P384_KEY, &[TlsSigScheme::EcdsaP384Sha384]),
        )
        .unwrap();
        validate(vec![der(RSA_CERT)], KeySigner::new(RSA_KEY, &ALL_RSA)).unwrap();
        // The intermediate does not need to match the leaf's key type.
        validate(
            vec![der(P256_CERT), der(RSA_CERT)],
            KeySigner::new(P256_KEY, &[TlsSigScheme::EcdsaP256Sha256]),
        )
        .unwrap();
    }

    #[test]
    fn validate_rejects_a_scheme_the_signer_fails_to_sign() {
        let error = validate(
            vec![der(P256_CERT)],
            unusable_signer(&[TlsSigScheme::EcdsaP256Sha256]),
        )
        .unwrap_err();

        assert_eq!(
            error,
            ClientCertificateError::SigningFailed {
                scheme: TlsSigScheme::EcdsaP256Sha256,
                reason: "Client certificate signing failed: key unavailable".to_owned(),
            }
        );
    }

    #[test]
    fn validate_rejects_a_signer_whose_key_does_not_match_the_leaf() {
        let error = validate(
            vec![der(P256_CERT)],
            KeySigner::new(P256_OTHER_KEY, &[TlsSigScheme::EcdsaP256Sha256]),
        )
        .unwrap_err();

        assert_eq!(
            error,
            ClientCertificateError::KeyMismatch {
                scheme: TlsSigScheme::EcdsaP256Sha256,
            }
        );
    }

    #[test]
    fn validate_rejects_an_empty_chain() {
        let error = validate(vec![], unusable_signer(&[TlsSigScheme::EcdsaP256Sha256]));

        assert_eq!(error, Err(ClientCertificateError::EmptyChain));
    }

    #[test]
    fn validate_rejects_unparseable_certificates() {
        let leaf = der(P256_CERT);
        let mut trailing = leaf.clone();
        trailing.push(0);

        for (chain, index) in [
            (vec![b"not a certificate".to_vec()], 0),
            (vec![leaf[..leaf.len() - 1].to_vec()], 0),
            (vec![trailing], 0),
            (vec![leaf, b"not a certificate".to_vec()], 1),
        ] {
            let error = validate(chain, unusable_signer(&[TlsSigScheme::EcdsaP256Sha256]));

            assert_eq!(
                error,
                Err(ClientCertificateError::InvalidCertificate { index })
            );
        }
    }

    #[test]
    fn validate_rejects_schemes_for_another_key_type() {
        for (certificate, schemes) in [
            (P256_CERT, vec![TlsSigScheme::EcdsaP384Sha384]),
            (P256_CERT, vec![TlsSigScheme::RsaPssSha256]),
            (P256_CERT, vec![]),
            (RSA_CERT, vec![TlsSigScheme::EcdsaP256Sha256]),
        ] {
            let error = validate(vec![der(certificate)], unusable_signer(&schemes));

            assert_eq!(
                error,
                Err(ClientCertificateError::NoCompatibleScheme),
                "{schemes:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_an_unsupported_key_type() {
        let error = validate(
            vec![der(ED25519_CERT)],
            unusable_signer(&[TlsSigScheme::EcdsaP256Sha256]),
        );

        assert_eq!(error, Err(ClientCertificateError::UnsupportedKey));
    }
}
