//! Runs the whole connector against wiremock identity and API servers to rotate an account on a
//! real domain controller. The Active Directory target's credentials come from the environment.
//! Every test is `#[ignore]`d; run them with:
//!
//! ```text
//! BWAC_AD_LIVE_HOST=dc01.example.com:636 \
//! BWAC_AD_LIVE_BIND_DN='CN=svc-rotate,OU=Service Accounts,DC=example,DC=com' \
//! BWAC_AD_LIVE_BASE_DN='OU=Managed,DC=example,DC=com' \
//! BWAC_AD_LIVE_BIND_PASSWORD='…' \
//! BWAC_AD_LIVE_ACCOUNT='svc-app' \
//! BWAC_AD_LIVE_ACCOUNT_PASSWORD='current password of that account' \
//! BWAC_AD_LIVE_CA=/path/to/dc-ca.pem \
//!   cargo test -p bitwarden-access-connector --all-features \
//!   --test active_directory_integration -- --ignored --test-threads=1
//! ```
//!
//! The run **changes the password of `BWAC_AD_LIVE_ACCOUNT`**, so use a disposable account.

mod common;

use std::{
    io,
    path::Path,
    sync::{Arc, Mutex},
};

use bitwarden_pam_sealed::{
    RotationConfigSealedV1, SealedPasswordPolicy, SealedTargetSystemKind, SealedTargetSystemMethod,
    TargetSystemSealedV1,
};
use common::*;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, ldap_escape};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject as _},
};

const LDAP_SUCCESS: u32 = 0;
const LDAP_INVALID_CREDENTIALS: u32 = 49;

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

    /// The connector's per-target variables for `target_id`.
    fn vars(&self, target_id: Uuid) -> Vec<(String, String)> {
        let prefix = env_prefix(target_id);
        let mut vars = vec![
            (format!("{prefix}LDAP_HOST"), self.host.clone()),
            (format!("{prefix}BIND_DN"), self.bind_dn.clone()),
            (format!("{prefix}BASE_DN"), self.base_dn.clone()),
            (format!("{prefix}BIND_PASSWORD"), self.bind_password.clone()),
        ];
        if let Some(ca) = &self.ca_certificate {
            vars.push((format!("{prefix}CA_CERTIFICATE"), ca.clone()));
        }
        vars
    }

    fn claim(
        &self,
        org_key: &bitwarden_crypto::SymmetricCryptoKey,
        attempt_id: Uuid,
        job_id: Uuid,
        target_id: Uuid,
    ) -> serde_json::Value {
        let target = TargetSystemSealedV1 {
            target_system_id: target_id,
            method: SealedTargetSystemMethod::Automatic,
            kind: Some(SealedTargetSystemKind::ActiveDirectory),
            password_policy: SealedPasswordPolicy {
                min_length: 32,
                max_length: 32,
                include_uppercase: true,
                include_lowercase: true,
                include_digits: true,
                include_symbols: true,
            },
            supports_session_termination: Some(false),
        };
        let config = RotationConfigSealedV1 {
            target_system_id: target_id,
            cipher_id: KEYED_LOGIN_ID,
            account_identity: self.account.clone(),
            terminate_sessions: false,
        };
        let sealed = seal_claim(org_key, target, config);
        claim_body_from(attempt_id, job_id, target_id, KEYED_LOGIN_ID, &sealed)
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

/// Mounts one rotation exchange. Only the first claim succeeds and later ones lose the race with a
/// 409, so a run rotates the account exactly once and the cipher write holds the new password.
async fn mount_single_rotation(
    api: &MockServer,
    claim: serde_json::Value,
    cipher: &serde_json::Value,
    job_id: Uuid,
    attempt_id: Uuid,
    target_id: Uuid,
) {
    let json = |body: serde_json::Value| ResponseTemplate::new(200).set_body_json(body);

    Mock::given(method("GET"))
        .and(path("/access-connectors/rotation/jobs"))
        .respond_with(json(serde_json::json!({
            "data": [{"jobId": job_id, "targetSystemId": target_id}]
        })))
        .mount(api)
        .await;

    let claim_path = format!("/access-connectors/rotation/jobs/{job_id}/claim");
    Mock::given(method("POST"))
        .and(path(claim_path.clone()))
        .respond_with(json(claim))
        .up_to_n_times(1)
        .mount(api)
        .await;
    Mock::given(method("POST"))
        .and(path(claim_path))
        .respond_with(ResponseTemplate::new(409))
        .mount(api)
        .await;

    let attempt = format!("/access-connectors/rotation/attempts/{attempt_id}");
    Mock::given(method("GET"))
        .and(path(format!("{attempt}/cipher")))
        .respond_with(json(cipher.clone()))
        .mount(api)
        .await;
    for (verb, route) in [("PUT", "cipher"), ("POST", "success"), ("POST", "failure")] {
        Mock::given(method(verb))
            .and(path(format!("{attempt}/{route}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(api)
            .await;
    }
}

/// Runs one rotation through the connector. Returns the password it wrote to the cipher, or the
/// failure report.
async fn rotate(target: &LiveTarget) -> Result<String, serde_json::Value> {
    let identity = MockServer::start().await;
    let api = MockServer::start().await;
    let (org_key, encrypted_payload) = org_key_and_payload();
    mount_identity_ok(&identity, &encrypted_payload).await;

    let (job_id, attempt_id, target_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let cipher = keyed_login_json();
    let claim = target.claim(&org_key, attempt_id, job_id, target_id);
    mount_single_rotation(&api, claim, &cipher, job_id, attempt_id, target_id).await;

    run_access_connector_with_env(
        &api,
        &identity,
        None,
        target.vars(target_id),
        Duration::from_secs(60),
    )
    .await;

    let requests = api.received_requests().await.expect("recording is on");
    let find = |verb: &str, suffix: &str| {
        requests
            .iter()
            .find(|r| r.method.as_str() == verb && r.url.path().ends_with(suffix))
    };
    if let Some(failure) = find("POST", "/failure") {
        return Err(failure.body_json().expect("the failure report is JSON"));
    }
    assert!(
        find("POST", "/success").is_some(),
        "the connector reported no outcome"
    );

    let write: serde_json::Value = find("PUT", "/cipher")
        .expect("a success follows the cipher write")
        .body_json()
        .expect("the cipher write is JSON");
    let original_key = cipher["key"].as_str().expect("the vector carries a key");
    assert_cipher_write_rotated(&org_key, &write, original_key, "old-password");
    Ok(decrypt_cipher_write_field(
        &org_key,
        &write,
        original_key,
        "/login/password",
    ))
}

/// A TLS config that trusts only the `BWAC_AD_LIVE_CA` anchors.
fn tls_config(ca_path: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let anchors =
        CertificateDer::pem_file_iter(Path::new(ca_path)).expect("the CA file is readable");
    for anchor in anchors {
        roots
            .add(anchor.expect("the CA file holds PEM certificates"))
            .expect("the CA file holds valid trust anchors");
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Arc::new(config)
}

/// The result code of a simple bind as the account with `password`. The service account looks up
/// the account's DN first, as the connector does.
async fn bind_as_account(target: &LiveTarget, password: &str) -> u32 {
    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(15));
    if let Some(ca) = &target.ca_certificate {
        settings = settings.set_config(tls_config(ca));
    }
    let url = format!("ldaps://{}", target.host);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .expect("the domain controller accepts the connection");
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });

    ldap.simple_bind(&target.bind_dn, &target.bind_password)
        .await
        .and_then(|r| r.success())
        .expect("the service account binds");
    let account = ldap_escape(target.account.as_str());
    let filter = format!(
        "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={account})(userPrincipalName={account})))"
    );
    let (entries, _) = ldap
        .search(&target.base_dn, Scope::Subtree, &filter, vec!["1.1"])
        .await
        .and_then(|r| r.success())
        .expect("the account lookup succeeds");
    let mut dns = entries
        .into_iter()
        .filter(|e| !e.is_ref() && !e.is_intermediate())
        .map(|e| SearchEntry::construct(e).dn);
    let (Some(dn), None) = (dns.next(), dns.next()) else {
        panic!("exactly one user must match BWAC_AD_LIVE_ACCOUNT");
    };

    let rc = ldap
        .simple_bind(&dn, password)
        .await
        .expect("the bind gets a response")
        .rc;
    let _ = ldap.unbind().await;
    rc
}

/// Rotates twice, then checks that no password reaches the log stream, that the password written
/// to the cipher binds, and that the pre-rotation password doesn't.
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

    let first_password = rotate(&target)
        .await
        .expect("the first rotation must succeed");
    let second_password = rotate(&target)
        .await
        .expect("a second rotation must succeed");

    // Read before the binds below, so the leak check covers only the connector's logging.
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
        ("bind password", target.bind_password.as_str()),
        ("account password", target.account_password.as_str()),
        ("first rotated password", first_password.as_str()),
        ("second rotated password", second_password.as_str()),
    ] {
        assert!(
            !logged.contains(secret),
            "{label} appeared in the log stream ({} bytes captured)",
            logged.len()
        );
    }

    assert_eq!(
        bind_as_account(&target, &second_password).await,
        LDAP_SUCCESS,
        "the password written to the cipher must bind"
    );

    // Without this, the checks above would also pass against a directory that accepts anything.
    assert_eq!(
        bind_as_account(&target, &Uuid::new_v4().to_string()).await,
        LDAP_INVALID_CREDENTIALS,
        "a password the account never had must not bind"
    );

    // Two rotations old. The immediately preceding password isn't asserted on: AD keeps accepting
    // it for `OldPasswordAllowedPeriod` (60 minutes by default).
    assert_eq!(
        bind_as_account(&target, &target.account_password).await,
        LDAP_INVALID_CREDENTIALS,
        "the pre-rotation password must no longer bind"
    );
}

/// The detail is asserted exactly, because a wrong bind DN or base DN would also fail before the
/// write and leave the target unchanged. On a host whose platform roots already trust the domain
/// controller, this fails after rotating the account.
#[tokio::test]
#[ignore = "requires a live Active Directory domain controller; see the module docs"]
async fn live_rotation_without_the_trust_anchor_is_refused() {
    let mut target = LiveTarget::from_env()
        .expect("BWAC_AD_LIVE_* environment variables must be set for the live test");
    target.ca_certificate = None;

    // Not `expect_err`, which would print the rotated password.
    let Err(report) = rotate(&target).await else {
        panic!("an untrusted certificate must not be accepted");
    };
    assert_eq!(
        report["detail"], "error kind: TlsHandshakeFailed",
        "the connection must fail on trust grounds, not for some other reason before the write: \
         {report}"
    );
    assert_eq!(report["errorCode"], "target_unreachable", "{report}");
    assert_eq!(
        report["syncState"], 0,
        "the target must be reported unchanged: {report}"
    );
}
