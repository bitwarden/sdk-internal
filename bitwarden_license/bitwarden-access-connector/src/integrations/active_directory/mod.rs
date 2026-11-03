//! On-premises Active Directory, rotated by an administrative reset of the account's `unicodePwd`
//! over LDAPS.
//!
//! `rotate` connects to `LDAP_HOST` and binds as the delegated service account in `BIND_DN`. It
//! searches below `BASE_DN` for the one user whose `sAMAccountName` or `userPrincipalName` is the
//! account identity, then replaces that user's `unicodePwd` with the new password. A reset doesn't
//! need the current password and isn't checked against password history, so a retry can resend the
//! same password. `verify` opens a new session, finds the account again and binds as it with the
//! new password. Session termination isn't supported, since a reset can't revoke Kerberos tickets
//! already issued.
//!
//! Every connection is LDAPS and trusts the platform roots plus any `CA_CERTIFICATE` anchors. There
//! is no plaintext, StartTLS or skip-verification path, since a domain controller refuses a
//! `unicodePwd` write without encryption anyway.
//!
//! What a failure says about the target depends on its `Phase`. A failure before the write and a
//! rejected write both leave the target unchanged, while a write that got no answer may have
//! landed. A permanent rejection that follows an unanswered write in the same attempt is settled by
//! binding as the account with the new password. Operator-facing behaviour is in the crate README.

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
    password_write::{UnsettledWrites, apply_password_write},
    session::{LdapSession, Timeouts, ldaps_url},
};
use super::{Integration, IntegrationError, RotateContext, TargetEffect};
use crate::{
    error::{Retry, SafeDetail},
    resolver::{
        ResolvedCredentials,
        env::{
            BASE_DN_SUFFIX, BIND_DN_SUFFIX, BIND_PASSWORD_SUFFIX, CA_CERTIFICATE_SUFFIX,
            LDAP_HOST_SUFFIX,
        },
    },
};

/// ldap3 sets no connect or operation timeout, so without these a domain controller that stops
/// answering would hang the rotation.
const TIMEOUTS: Timeouts = Timeouts {
    connect: Duration::from_secs(15),
    operation: Duration::from_secs(30),
};

/// The [`Integration`] for Active Directory targets.
#[derive(Debug)]
pub(crate) struct ActiveDirectoryIntegration {
    timeouts: Timeouts,
    unsettled_writes: UnsettledWrites,
}

impl ActiveDirectoryIntegration {
    pub(crate) fn new() -> Self {
        Self {
            timeouts: TIMEOUTS,
            unsettled_writes: UnsettledWrites::default(),
        }
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
            url: ldaps_url(get_cred(creds, LDAP_HOST_SUFFIX)?)?,
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
        let written = apply_password_write(
            &mut session,
            &account_dn,
            &ctx.new_password,
            self.unsettled_writes.contains(ctx),
        )
        .await;
        self.unsettled_writes.record(ctx, &written);
        written?;
        session.close().await;
        Ok(())
    }

    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        // A bind with the new password can't be stale, unlike an attribute read.
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

    async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        // AD targets are sealed without session termination, since a reset can't revoke Kerberos
        // tickets already issued, so the executor never calls this.
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
    use crate::integrations::active_directory::test_support::SENTINEL_PASSWORD;

    fn make_ctx(creds: ResolvedCredentials) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "svc-app".to_string(),
            new_password: SENTINEL_PASSWORD.to_string(),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn complete_creds(host: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert(LDAP_HOST_SUFFIX.to_string(), host.to_string());
        creds.insert(BIND_DN_SUFFIX.to_string(), "CN=svc,DC=corp".to_string());
        creds.insert(BASE_DN_SUFFIX.to_string(), "DC=corp".to_string());
        creds.insert(
            BIND_PASSWORD_SUFFIX.to_string(),
            SENTINEL_PASSWORD.to_string(),
        );
        creds
    }

    #[test]
    fn integration_debug_holds_no_secrets() {
        let integration = ActiveDirectoryIntegration::new();
        let debug = format!("{integration:?}");
        assert!(
            !debug.contains(SENTINEL_PASSWORD),
            "debug leaked a secret: {debug}"
        );
    }

    #[tokio::test]
    async fn rotate_context_debug_redacts_the_new_password() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            BIND_PASSWORD_SUFFIX.to_string(),
            SENTINEL_PASSWORD.to_string(),
        );
        let ctx = make_ctx(creds);
        let debug = format!("{ctx:?}");
        assert!(
            !debug.contains(SENTINEL_PASSWORD),
            "password leaked: {debug}"
        );
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
        assert!(!err.to_string().contains(SENTINEL_PASSWORD));
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
