//! On-premises Active Directory: an administrative reset of `unicodePwd` over LDAPS, bound as a
//! delegated service account. There is no plaintext, StartTLS or skip-verification path, since a
//! domain controller refuses the write without encryption anyway. Operator-facing behaviour is in
//! the crate README.

mod classify;
mod password_write;
mod session;
#[cfg(test)]
mod test_support;
mod tls;

use std::time::Duration;

use async_trait::async_trait;
use bitwarden_pam::RotationFailureCode;
use bitwarden_sensitive_value::ExposeSensitive as _;
use ldap3::LdapError;

use self::{
    classify::{Phase, classify_ldap_error},
    password_write::apply_password_write,
    session::{LdapSession, Timeouts, ldaps_url},
};
use super::{Integration, IntegrationError, RotateContext, TargetEffect};
use crate::{
    error::{Retry, SafeDetail},
    resolver::ResolvedCredentials,
};

const HOST_SUFFIX: &str = "LDAP_HOST";
const BIND_DN_SUFFIX: &str = "BIND_DN";
const BASE_DN_SUFFIX: &str = "BASE_DN";
const BIND_PASSWORD_SUFFIX: &str = "BIND_PASSWORD";
const CA_CERTIFICATE_SUFFIX: &str = "CA_CERTIFICATE";

const TIMEOUTS: Timeouts = Timeouts {
    connect: Duration::from_secs(15),
    operation: Duration::from_secs(30),
};

/// Holds no credentials; each operation reads them from `ctx.creds`.
#[derive(Debug)]
pub(crate) struct ActiveDirectoryIntegration {
    timeouts: Timeouts,
}

impl ActiveDirectoryIntegration {
    pub(crate) fn new() -> Self {
        Self { timeouts: TIMEOUTS }
    }
}

struct Credentials<'a> {
    url: String,
    bind_dn: &'a str,
    base_dn: &'a str,
    bind_password: &'a str,
    /// A PEM file of extra trust anchors for a DC with a private or self-signed certificate.
    ca_certificate: Option<&'a str>,
}

impl<'a> Credentials<'a> {
    fn resolve(creds: &'a ResolvedCredentials) -> Result<Self, IntegrationError> {
        Ok(Self {
            url: ldaps_url(get_cred(creds, HOST_SUFFIX)?)?,
            bind_dn: get_cred(creds, BIND_DN_SUFFIX)?,
            base_dn: get_cred(creds, BASE_DN_SUFFIX)?,
            bind_password: get_cred(creds, BIND_PASSWORD_SUFFIX)?,
            ca_certificate: optional_cred(creds, CA_CERTIFICATE_SUFFIX),
        })
    }
}

fn optional_cred<'a>(creds: &'a ResolvedCredentials, suffix: &'static str) -> Option<&'a str> {
    creds.get(suffix).map(|s| s.expose().as_ref() as &str)
}

fn get_cred<'a>(
    creds: &'a ResolvedCredentials,
    suffix: &'static str,
) -> Result<&'a str, IntegrationError> {
    optional_cred(creds, suffix).ok_or_else(|| {
        IntegrationError::new(
            Retry::Permanent,
            TargetEffect::NotApplied,
            RotationFailureCode::CredentialsUnresolved,
            SafeDetail::from_kind(suffix),
        )
    })
}

fn as_applied(mut err: IntegrationError) -> IntegrationError {
    err.effect = TargetEffect::Applied;
    err
}

#[async_trait]
impl Integration for ActiveDirectoryIntegration {
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds)?;
        let (mut session, account_dn) = LdapSession::open_and_locate(
            &creds,
            &ctx.account_identity,
            self.timeouts,
            Phase::BeforeWrite,
        )
        .await?;
        apply_password_write(&mut session, &account_dn, &ctx.new_password).await?;
        session.close().await;
        Ok(())
    }

    /// Binds as the rotated account with the new password, which unlike an attribute read can't be
    /// stale.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds).map_err(as_applied)?;
        let (mut session, account_dn) = LdapSession::open_and_locate(
            &creds,
            &ctx.account_identity,
            self.timeouts,
            Phase::AfterWrite,
        )
        .await?;
        let bind = session.simple_bind(&account_dn, &ctx.new_password).await;
        session.close().await;

        match bind {
            Ok(()) => Ok(()),
            Err(LdapError::LdapResult { result }) => Err(IntegrationError::new(
                Retry::Permanent,
                TargetEffect::Applied,
                RotationFailureCode::VerificationFailed,
                SafeDetail::from_ldap_result_code(result.rc),
            )),
            Err(other) => Err(classify_ldap_error(&other, Phase::AfterWrite)),
        }
    }

    /// A password reset can't revoke Kerberos tickets already issued, so AD targets are sealed
    /// without session termination and this is never reached.
    async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        Err(IntegrationError::new(
            Retry::Permanent,
            TargetEffect::NotApplied,
            RotationFailureCode::UnsupportedKind,
            SafeDetail::from_kind("ActiveDirectorySessionTerminationUnsupported"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::integrations::active_directory::test_support::SECRET;

    fn make_ctx(creds: ResolvedCredentials) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "svc-app".to_string(),
            new_password: SECRET.to_string(),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn complete_creds(host: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert(HOST_SUFFIX.to_string(), host.to_string());
        creds.insert(BIND_DN_SUFFIX.to_string(), "CN=svc,DC=corp".to_string());
        creds.insert(BASE_DN_SUFFIX.to_string(), "DC=corp".to_string());
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), SECRET.to_string());
        creds
    }

    #[test]
    fn integration_debug_holds_no_secrets() {
        let integration = ActiveDirectoryIntegration::new();
        let debug = format!("{integration:?}");
        assert!(!debug.contains(SECRET), "debug leaked a secret: {debug}");
    }

    #[tokio::test]
    async fn rotate_context_debug_redacts_the_new_password() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), SECRET.to_string());
        let ctx = make_ctx(creds);
        let debug = format!("{ctx:?}");
        assert!(!debug.contains(SECRET), "password leaked: {debug}");
    }

    #[tokio::test]
    async fn missing_credential_error_names_the_suffix_only() {
        let integration = ActiveDirectoryIntegration::new();
        let ctx = make_ctx(ResolvedCredentials::new());
        let err = integration
            .rotate(&ctx)
            .await
            .expect_err("empty credentials must fail before connecting");
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.detail.as_str(), "error kind: LDAP_HOST");
    }

    #[tokio::test]
    async fn malformed_host_fails_before_connecting() {
        let integration = ActiveDirectoryIntegration::new();
        let ctx = make_ctx(complete_creds("ldap://dc01"));

        let err = integration
            .rotate(&ctx)
            .await
            .expect_err("a non-LDAPS host must be refused");
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: MalformedLdapHost");
        assert!(!err.to_string().contains(SECRET));
    }

    #[test]
    fn ca_certificate_is_optional_and_absent_by_default() {
        let creds = complete_creds("dc01.corp.example");

        let resolved = Credentials::resolve(&creds).expect("credentials resolve without a CA");
        assert!(
            resolved.ca_certificate.is_none(),
            "an absent CA_CERTIFICATE must leave the connection on platform roots"
        );
    }

    #[test]
    fn ca_certificate_is_picked_up_when_present() {
        let mut creds = complete_creds("dc01.corp.example");
        creds.insert(
            CA_CERTIFICATE_SUFFIX.to_string(),
            "/etc/pki/ad-ca.pem".to_string(),
        );

        let resolved = Credentials::resolve(&creds).expect("credentials resolve");
        assert_eq!(resolved.ca_certificate, Some("/etc/pki/ad-ca.pem"));
    }

    #[tokio::test]
    async fn terminate_sessions_is_unsupported() {
        let integration = ActiveDirectoryIntegration::new();
        let ctx = make_ctx(ResolvedCredentials::new());
        let err = integration
            .terminate_sessions(&ctx)
            .await
            .expect_err("session termination is not supported for Active Directory");
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.code, RotationFailureCode::UnsupportedKind);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(
            err.detail.as_str(),
            "error kind: ActiveDirectorySessionTerminationUnsupported"
        );
    }
}
