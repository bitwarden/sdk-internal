use bitwarden_pam::RotationFailureCode;
use ldap3::LdapError;

use crate::{
    error::{Retry, SafeDetail},
    integrations::{IntegrationError, TargetEffect},
};

// LDAP result codes, RFC 4511 §A.1.
const RC_ADMIN_LIMIT_EXCEEDED: u32 = 11;
const RC_BUSY: u32 = 51;
const RC_UNAVAILABLE: u32 = 52;
pub(super) const RC_INVALID_CREDENTIALS: u32 = 49;

/// Where in a rotation an LDAP failure happened, which decides what it says about the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// Connect, bind and account lookup; nothing has been written.
    BeforeWrite,
    /// The `unicodePwd` write.
    Write,
    /// After a successful write.
    AfterWrite,
}

impl Phase {
    /// The effect when the outcome is known: the directory answered, or nothing was sent.
    pub(super) fn settled(self) -> TargetEffect {
        match self {
            Self::BeforeWrite | Self::Write => TargetEffect::NotApplied,
            Self::AfterWrite => TargetEffect::Applied,
        }
    }

    /// The effect when the request may have gone out before the failure.
    fn indeterminate(self) -> TargetEffect {
        match self {
            Self::BeforeWrite => TargetEffect::NotApplied,
            Self::Write => TargetEffect::Unknown,
            Self::AfterWrite => TargetEffect::Applied,
        }
    }
}

/// Transport failures are transient; directory decisions and TLS or configuration failures are
/// permanent. Only a result code or a fixed kind reaches the detail, never the directory's text,
/// which can echo account names.
pub(super) fn classify_ldap_error(err: &LdapError, phase: Phase) -> IntegrationError {
    let settled = phase.settled();
    let indeterminate = phase.indeterminate();
    match err {
        LdapError::Io { source } if is_tls_error(source) => {
            target_unreachable(Retry::Permanent, indeterminate, "TlsHandshakeFailed")
        }
        LdapError::Io { source } => target_unreachable(
            Retry::Transient,
            indeterminate,
            io_error_kind_name(source.kind()),
        ),
        LdapError::Timeout { .. } => {
            target_unreachable(Retry::Transient, indeterminate, "OperationTimeout")
        }
        LdapError::EndOfStream
        | LdapError::OpSend { .. }
        | LdapError::ResultRecv { .. }
        | LdapError::IdScrubSend { .. }
        | LdapError::MiscSend { .. } => {
            target_unreachable(Retry::Transient, indeterminate, "ConnectionClosed")
        }
        // ldap3 0.12 reports TLS failures as `Io`; this arm guards a future version.
        LdapError::Rustls { .. } => {
            target_unreachable(Retry::Permanent, indeterminate, "TlsHandshakeFailed")
        }
        LdapError::DNSName { .. } => {
            target_unreachable(Retry::Permanent, settled, "TlsInvalidServerName")
        }
        LdapError::UrlParsing { .. }
        | LdapError::UnknownScheme(_)
        | LdapError::EmptyUnixPath
        | LdapError::PortInUnixPath
        | LdapError::MismatchedStreamType => IntegrationError::new(
            Retry::Permanent,
            settled,
            RotationFailureCode::CredentialsUnresolved,
            SafeDetail::from_kind("MalformedLdapHost"),
        ),
        LdapError::LdapResult { result } => classify_result_code(result.rc, phase),
        _ => IntegrationError::new(
            Retry::Permanent,
            settled,
            RotationFailureCode::Internal,
            SafeDetail::from_kind("LdapClientError"),
        ),
    }
}

/// Load shedding is transient; any other rejection is a decision the directory will repeat.
fn classify_result_code(rc: u32, phase: Phase) -> IntegrationError {
    let (retry, code) = match rc {
        RC_ADMIN_LIMIT_EXCEEDED | RC_BUSY | RC_UNAVAILABLE => {
            (Retry::Transient, RotationFailureCode::TargetUnreachable)
        }
        _ => (Retry::Permanent, RotationFailureCode::TargetRejected),
    };
    IntegrationError::new(
        retry,
        phase.settled(),
        code,
        SafeDetail::from_ldap_result_code(rc),
    )
}

pub(super) fn target_rejected(effect: TargetEffect, kind: &'static str) -> IntegrationError {
    IntegrationError::new(
        Retry::Permanent,
        effect,
        RotationFailureCode::TargetRejected,
        SafeDetail::from_kind(kind),
    )
}

fn target_unreachable(retry: Retry, effect: TargetEffect, kind: &'static str) -> IntegrationError {
    IntegrationError::new(
        retry,
        effect,
        RotationFailureCode::TargetUnreachable,
        SafeDetail::from_kind(kind),
    )
}

/// tokio-rustls reports a rejected certificate as `io::Error(InvalidData, rustls::Error)`, which
/// ldap3 forwards as `Io`. It must not be retried like a network fault: it needs an operator.
fn is_tls_error(source: &std::io::Error) -> bool {
    source
        .get_ref()
        .is_some_and(|inner| inner.is::<rustls::Error>())
}

fn io_error_kind_name(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused => "ConnectionRefused",
        ErrorKind::ConnectionReset => "ConnectionReset",
        ErrorKind::ConnectionAborted => "ConnectionAborted",
        ErrorKind::NotConnected => "NotConnected",
        ErrorKind::BrokenPipe => "BrokenPipe",
        ErrorKind::TimedOut => "ConnectTimeout",
        ErrorKind::UnexpectedEof => "UnexpectedEof",
        _ => "NetworkError",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::integrations::active_directory::test_support::{SECRET, ldap_result};

    #[test]
    fn directory_rejections_are_fatal() {
        // 13 confidentialityRequired, 19 constraintViolation, 32 noSuchObject,
        // 49 invalidCredentials, 50 insufficientAccessRights, 53 unwillingToPerform,
        // 16/17/21 schema errors.
        for rc in [13, 16, 17, 19, 21, 32, 49, 50, 53] {
            let err = classify_result_code(rc, Phase::BeforeWrite);
            assert_eq!(err.retry, Retry::Permanent, "rc {rc} must be fatal");
            assert_eq!(err.code, RotationFailureCode::TargetRejected, "rc {rc}");
            assert_eq!(err.effect, TargetEffect::NotApplied, "rc {rc}");
        }
    }

    #[test]
    fn load_shedding_codes_are_transient() {
        for rc in [RC_ADMIN_LIMIT_EXCEEDED, RC_BUSY, RC_UNAVAILABLE] {
            let err = classify_result_code(rc, Phase::BeforeWrite);
            assert_eq!(err.retry, Retry::Transient, "rc {rc} must be transient");
            assert_eq!(err.code, RotationFailureCode::TargetUnreachable, "rc {rc}");
        }
    }

    #[test]
    fn network_errors_are_transient() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            },
            Phase::BeforeWrite,
        );
        assert_eq!(err.retry, Retry::Transient);
        assert_eq!(err.code, RotationFailureCode::TargetUnreachable);
        assert_eq!(err.detail.as_str(), "error kind: ConnectionRefused");
    }

    #[test]
    fn dropped_connection_during_modify_is_unknown_not_not_applied() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            },
            Phase::Write,
        );
        assert_eq!(
            err.effect,
            TargetEffect::Unknown,
            "a transport failure after the modify is sent leaves the outcome unknown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn operation_timeout_during_modify_is_unknown() {
        let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
            .await
            .expect_err("must elapse");
        let err = classify_ldap_error(&LdapError::from(elapsed), Phase::Write);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.retry, Retry::Transient);
        assert_eq!(err.detail.as_str(), "error kind: OperationTimeout");
    }

    #[test]
    fn rejected_certificate_is_fatal_not_transient() {
        let rustls_err = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err),
            },
            Phase::BeforeWrite,
        );
        assert_eq!(
            err.retry,
            Retry::Permanent,
            "an untrusted certificate must not be retried as a network blip"
        );
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.detail.as_str(), "error kind: TlsHandshakeFailed");
    }

    #[test]
    fn tls_failure_during_the_modify_leaves_the_effect_unknown() {
        let rustls_err = rustls::Error::InvalidCertificate(rustls::CertificateError::Expired);
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err),
            },
            Phase::Write,
        );
        assert_eq!(err.effect, TargetEffect::Unknown);
    }

    #[test]
    fn plain_io_errors_stay_transient() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not a tls error"),
            },
            Phase::BeforeWrite,
        );
        assert_eq!(err.retry, Retry::Transient);
    }

    #[test]
    fn tls_failures_are_fatal() {
        let err = classify_ldap_error(
            &LdapError::DNSName {
                source: rustls::pki_types::ServerName::try_from("not a host name")
                    .expect_err("must be invalid"),
            },
            Phase::BeforeWrite,
        );
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.detail.as_str(), "error kind: TlsInvalidServerName");
    }

    #[test]
    fn errors_after_rotation_report_applied() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(49, "invalid credentials"),
            },
            Phase::AfterWrite,
        );
        assert_eq!(err.effect, TargetEffect::Applied);
    }

    #[test]
    fn detail_carries_only_the_result_code_not_directory_text() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(53, &format!("rejected password {SECRET}")),
            },
            Phase::Write,
        );
        assert_eq!(err.detail.as_str(), "LDAP result code 53");
        let rendered = err.to_string();
        assert!(!rendered.contains(SECRET), "password leaked: {rendered}");
        assert!(
            !rendered.contains("OU=Service Accounts"),
            "matched DN leaked: {rendered}"
        );
    }
}
