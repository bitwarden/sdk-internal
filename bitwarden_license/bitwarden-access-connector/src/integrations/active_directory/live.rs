//! End-to-end checks against a real domain controller. Every test is `#[ignore]`d; run them with:
//!
//! ```text
//! BWAC_AD_LIVE_HOST=dc01.example.com:636 \
//! BWAC_AD_LIVE_BIND_DN='CN=svc-rotate,OU=Service Accounts,DC=example,DC=com' \
//! BWAC_AD_LIVE_BASE_DN='OU=Managed,DC=example,DC=com' \
//! BWAC_AD_LIVE_BIND_PASSWORD='…' \
//! BWAC_AD_LIVE_ACCOUNT='svc-app' \
//! BWAC_AD_LIVE_ACCOUNT_PASSWORD='current password of that account' \
//! BWAC_AD_LIVE_CA=/path/to/dc-ca.pem \
//!   cargo test -p bitwarden-access-connector --lib -- --ignored --exact \
//!   integrations::active_directory::live::live_rotation_against_a_real_domain_controller
//! ```
//!
//! The run **changes the password of `BWAC_AD_LIVE_ACCOUNT`**, so use a disposable account.

use std::{
    io,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use uuid::Uuid;

use super::*;

struct LiveTarget {
    host: String,
    bind_dn: String,
    base_dn: String,
    bind_password: String,
    ca_certificate: Option<String>,
    account: String,
    /// The account's password before the test runs.
    account_password: String,
}

impl LiveTarget {
    fn from_env() -> Option<Self> {
        let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
        Some(Self {
            host: var("BWAC_AD_LIVE_HOST")?,
            bind_dn: var("BWAC_AD_LIVE_BIND_DN")?,
            base_dn: var("BWAC_AD_LIVE_BASE_DN")?,
            bind_password: var("BWAC_AD_LIVE_BIND_PASSWORD")?,
            ca_certificate: var("BWAC_AD_LIVE_CA"),
            account: var("BWAC_AD_LIVE_ACCOUNT")?,
            account_password: var("BWAC_AD_LIVE_ACCOUNT_PASSWORD")?,
        })
    }

    fn creds(&self) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert(HOST_SUFFIX.to_string(), self.host.clone());
        creds.insert(BIND_DN_SUFFIX.to_string(), self.bind_dn.clone());
        creds.insert(BASE_DN_SUFFIX.to_string(), self.base_dn.clone());
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), self.bind_password.clone());
        if let Some(ca) = &self.ca_certificate {
            creds.insert(CA_CERTIFICATE_SUFFIX.to_string(), ca.clone());
        }
        creds
    }

    fn context(&self, password: &str) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: self.account.clone(),
            new_password: password.to_string(),
            creds: self.creds(),
            rotation_started_at: Utc::now(),
        }
    }
}

#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut guard) = self.0.lock() {
            guard.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Satisfies default AD complexity rules.
fn generated_password() -> String {
    format!("Bw!{}aQ9", Uuid::new_v4().simple())
}

/// Rotates twice, proves the new password works and the original doesn't, and that no password
/// reaches the log stream.
#[tokio::test]
#[ignore = "requires a live Active Directory domain controller; see the module docs"]
async fn live_rotation_against_a_real_domain_controller() {
    let target = LiveTarget::from_env()
        .expect("BWAC_AD_LIVE_* environment variables must be set for the live test");

    let captured = Arc::new(Mutex::new(Vec::new()));
    let _ = tracing_subscriber::fmt()
        .with_writer(CapturedLog(Arc::clone(&captured)))
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .try_init();
    tracing::info!("live-ad-capture-probe");

    let integration = ActiveDirectoryIntegration::new();
    let old_password = target.bind_password.clone();
    let new_password = generated_password();

    let rotate_ctx = target.context(&new_password);
    integration
        .rotate(&rotate_ctx)
        .await
        .expect("rotate must succeed against the live directory");

    integration
        .verify(&rotate_ctx)
        .await
        .expect("verify must rebind as the rotated account with the new password");

    let second_password = generated_password();
    let second_ctx = target.context(&second_password);
    integration
        .rotate(&second_ctx)
        .await
        .expect("a second rotation must succeed");
    integration
        .verify(&second_ctx)
        .await
        .expect("verify must succeed after the second rotation");

    // Without this, the checks above would also pass against a directory that accepts anything.
    let never_set = generated_password();
    let rejected = integration
        .verify(&target.context(&never_set))
        .await
        .expect_err("a password the account never had must not bind");
    assert_eq!(rejected.retry, Retry::Permanent);
    assert_eq!(rejected.code, RotationFailureCode::VerificationFailed);
    assert_eq!(rejected.effect, TargetEffect::Applied);

    // Two rotations old. The immediately preceding password isn't asserted on: AD keeps accepting
    // it for `OldPasswordAllowedPeriod` (60 minutes by default).
    let account_password = target.account_password.clone();
    let superseded = integration
        .verify(&target.context(&account_password))
        .await
        .expect_err("the pre-rotation password must no longer bind");
    assert_eq!(superseded.retry, Retry::Permanent);
    assert_eq!(superseded.code, RotationFailureCode::VerificationFailed);

    let logged = String::from_utf8_lossy(
        &captured
            .lock()
            .expect("captured log is not poisoned")
            .clone(),
    )
    .into_owned();

    assert!(
        logged.contains("live-ad-capture-probe"),
        "log capture must be active, otherwise the leak assertions below prove nothing"
    );
    for (label, secret) in [
        ("bind password", old_password.as_str()),
        ("account password", target.account_password.as_str()),
        ("first rotated password", new_password.as_str()),
        ("second rotated password", second_password.as_str()),
    ] {
        assert!(
            !logged.contains(secret),
            "{label} appeared in the log stream ({} bytes captured)",
            logged.len()
        );
    }
}

/// The detail is asserted exactly, because a wrong bind DN or base DN would also fail permanently
/// with `NotApplied`. It uses the account's current password, so a host that already trusts the
/// enterprise root doesn't leave the account on a discarded password.
#[tokio::test]
#[ignore = "requires a live Active Directory domain controller; see the module docs"]
async fn live_rotation_without_the_trust_anchor_is_refused() {
    let mut target = LiveTarget::from_env()
        .expect("BWAC_AD_LIVE_* environment variables must be set for the live test");
    target.ca_certificate = None;

    let integration = ActiveDirectoryIntegration::new();
    let ctx = target.context(&target.account_password);
    let err = integration
        .rotate(&ctx)
        .await
        .expect_err("an untrusted certificate must not be accepted");
    assert_eq!(
        err.detail.as_str(),
        "error kind: TlsHandshakeFailed",
        "the connection must fail on trust grounds, not for some other \
         reason before the write: {err}"
    );
    assert_eq!(
        err.code,
        RotationFailureCode::TargetUnreachable,
        "error was: {err}"
    );
    assert_eq!(err.retry, Retry::Permanent, "error was: {err}");
    assert_eq!(err.effect, TargetEffect::NotApplied, "error was: {err}");
}
