use std::{path::Path, sync::Arc};

use bitwarden_pam::RotationFailureCode;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject as _},
};
use rustls_platform_verifier::Verifier;

use super::classify::{Phase, target_unreachable};
use crate::{
    error::{Retry, SafeDetail},
    integrations::IntegrationError,
};

/// Verifies the DC's certificate with the platform verifier, the same one the connector's HTTPS
/// uses, plus the PEM file's anchors if given, never the file alone. Failing to load the file is
/// fatal rather than a quiet fallback to platform trust, and the error carries a fixed kind, never
/// the path.
pub(super) fn tls_config(
    ca_certificate: Option<&str>,
    phase: Phase,
) -> Result<Arc<ClientConfig>, IntegrationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = match ca_certificate {
        Some(path) => Verifier::new_with_extra_roots(read_anchors(path, phase)?, provider.clone()),
        None => Verifier::new(provider.clone()),
    }
    .map_err(|_| target_unreachable(Retry::Permanent, phase.settled(), "TlsVerifierUnavailable"))?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| anchor_failure(phase, "TlsProviderUnavailable"))?
        // rustls gates any non-default verifier behind `dangerous()`. This one is the platform
        // verifier, so the OS (or webpki over system roots on Linux) still checks chain and host.
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn read_anchors(
    path: &str,
    phase: Phase,
) -> Result<Vec<CertificateDer<'static>>, IntegrationError> {
    let anchors: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(Path::new(path))
        .map_err(|_| anchor_failure(phase, "CaCertificateUnreadable"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anchor_failure(phase, "CaCertificateInvalid"))?;
    if anchors.is_empty() {
        return Err(anchor_failure(phase, "CaCertificateEmpty"));
    }

    // Reject an unusable anchor here, as `CaCertificateInvalid`, not as a generic verifier error.
    let mut scratch = RootCertStore::empty();
    for anchor in &anchors {
        scratch
            .add(anchor.clone())
            .map_err(|_| anchor_failure(phase, "CaCertificateInvalid"))?;
    }
    Ok(anchors)
}

fn anchor_failure(phase: Phase, kind: &'static str) -> IntegrationError {
    IntegrationError::new(
        Retry::Permanent,
        phase.settled(),
        RotationFailureCode::CredentialsUnresolved,
        SafeDetail::from_kind(kind),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::TargetEffect;

    /// A self-signed certificate used only as a parseable trust anchor.
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDJTCCAg2gAwIBAgIUP9bWk+gm4n6VqzhqhQz9YDiwR/UwDQYJKoZIhvcNAQEL\n\
BQAwIjEgMB4GA1UEAwwXcm90YXRpb24tZGFlbW9uLXRlc3QtY2EwHhcNMjYwODMx\n\
MjIzODU5WhcNMzYwODI4MjIzODU5WjAiMSAwHgYDVQQDDBdyb3RhdGlvbi1kYWVt\n\
b24tdGVzdC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALCVyUmM\n\
86vormZ7E/vOxdZMvJOYVjp17OrAI1tPWq0PywOizZ1gJORWXjArJFT0PoG2OqmA\n\
hafaOoZTeZH0J4DwEjgGVn/rGVIa8f5a8qjfnJdDn23fnqa2Wd+9Tf1/LDeCUZil\n\
7jZ4NqtddZe+GOkkWJXB+55u7JhxPyX/AdfVK9idmGANXGuCOUZhTLSnz+p5SrLP\n\
WWDgQeAHTvFlWcpu8eff5Agj5cdhqyJiBcpaLzga0xiUifpdG4yEU/7H/909XKOQ\n\
/O0wiPwnObHwOVFALDppeHo9FtGmvK0OQArxgo40gaeWEvctURyXc6Lqu5u8eZXV\n\
MX5nIS+hPAYLZ50CAwEAAaNTMFEwHQYDVR0OBBYEFE7MLaoHaLKLcBeZsdAfGTk0\n\
0ToLMB8GA1UdIwQYMBaAFE7MLaoHaLKLcBeZsdAfGTk00ToLMA8GA1UdEwEB/wQF\n\
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJyvTvcTCL6s3MPlhYHrcCAfc6/PcVro\n\
NvLM9fOUvmlqdlyXyvwZ/FOwGogLUSVVR+68wLQ4NFac4nhyeaApiFsKoHP+bA6X\n\
bsgmmsTYuH0fw43szFTlI+Lw2a8Ai9Nx8JTeyILL9FzCV6ranWW7YcQBEPTvpfB7\n\
vBWeCGTA+sHqgBbltU/5jsWYslt9YhOpxkoJHHxyt2JA8XYCpdSkfgFOsjReofHn\n\
SavmVaBabR7Vq3QVTfvp+/WO41z7hGKsGAZ2dVldkHeOjgu4oktTOeblDbnZogZ2\n\
D2kYx4ka5O/dEuqcrMf/qd6GW5H2PJcrdc4PtRJeIBDR0TgweD2xjJ0=\n\
-----END CERTIFICATE-----\n";

    fn write_temp(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(contents.as_bytes()).expect("write pem");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn valid_ca_certificate_builds_a_client_config() {
        let f = write_temp(TEST_CA_PEM);
        let path = f.path().to_str().expect("utf8 path");
        assert!(tls_config(Some(path), Phase::BeforeWrite).is_ok());
    }

    #[test]
    fn no_ca_certificate_builds_a_client_config() {
        assert!(tls_config(None, Phase::BeforeWrite).is_ok());
    }

    #[test]
    fn missing_ca_certificate_file_is_fatal() {
        let err = tls_config(
            Some("/nonexistent/path/to/ca-bundle-2f8a1c.pem"),
            Phase::BeforeWrite,
        )
        .expect_err("a missing PEM must not fall back to platform roots");
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateUnreadable");
    }

    #[test]
    fn malformed_ca_certificate_is_fatal() {
        let truncated = "-----BEGIN CERTIFICATE-----\nMIIDJTCCAg2gAwIBAgIUP9bWk\n";
        let f = write_temp(truncated);
        let path = f.path().to_str().expect("utf8 path");
        let err = tls_config(Some(path), Phase::BeforeWrite)
            .expect_err("a malformed PEM must not fall back to platform roots");
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateInvalid");
    }

    #[test]
    fn ca_certificate_without_a_certificate_is_fatal() {
        let f = write_temp("# no PEM sections here\n");
        let path = f.path().to_str().expect("utf8 path");
        let err = tls_config(Some(path), Phase::BeforeWrite)
            .expect_err("a PEM with no certificate must not fall back to platform roots");
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateEmpty");
    }

    #[test]
    fn ca_certificate_path_never_reaches_the_error_detail() {
        let path = "/etc/secrets/ad-ca-9f3b2e.pem";
        let err = tls_config(Some(path), Phase::BeforeWrite).expect_err("missing file");
        assert!(
            !err.to_string().contains("9f3b2e"),
            "the configured path must not appear in the error: {err}"
        );
    }

    #[test]
    fn ca_certificate_failure_after_rotation_reports_applied() {
        let err =
            tls_config(Some("/nonexistent/ca.pem"), Phase::AfterWrite).expect_err("missing file");
        assert_eq!(err.effect, TargetEffect::Applied);
    }
}
