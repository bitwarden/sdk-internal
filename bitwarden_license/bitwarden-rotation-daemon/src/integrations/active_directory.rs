//! On-premises Active Directory integration for credential rotation.
//!
//! [`ActiveDirectoryIntegration`] rotates a domain account's password by
//! replacing the `unicodePwd` attribute over LDAPS, binding as a delegated
//! service account that holds reset-password rights on the target OU.
//!
//! # LDAPS is mandatory
//!
//! Every connection is opened with an `ldaps://` URL on port 636 (implicit TLS).
//! There is no plaintext LDAP path, no StartTLS fallback, and no
//! certificate-validation bypass. This is both a Bitwarden requirement and an
//! Active Directory one: a domain controller refuses a `unicodePwd` write on a
//! connection that is not encrypted, answering `confidentialityRequired`
//! (result code 13).
//!
//! The server certificate is validated against the host's native trust store.
//! A deployment whose domain controller uses a private or self-signed
//! certificate can name a PEM file of additional trust anchors with the
//! `CA_CERTIFICATE` credential; those anchors are **added** to the platform
//! roots, never substituted for them. There is deliberately no option to skip
//! verification or relax the host-name check — an extra anchor is the only
//! escape hatch offered.
//!
//! # Bind identity
//!
//! The bind DN is expected to be a **delegated service account** whose only
//! privilege on the target OU is `Reset Password` (plus read access to locate
//! the account). Binding as Domain Admin is not required and is not supported
//! as a recommendation — a daemon-held credential should never carry
//! domain-wide authority.
//!
//! # RotationByAdministrativeReset
//!
//! Replacing `unicodePwd` in a single `replace` modification is an
//! administrative reset: it does not require the account's current password.
//! The daemon never holds the rotated account's old credential, which is what
//! makes retries converge — see the `custom_script` module docs for the full
//! reasoning.
//!
//! # Session termination
//!
//! Not supported. An LDAP password reset cannot revoke already-issued Kerberos
//! ticket-granting tickets, so there is no honest implementation of
//! [`Integration::terminate_sessions`] for this kind; it returns a fatal error.
//! The server marks the Active Directory kind with
//! `supportsSessionTermination: false`, so the executor should never reach it.
//!
//! # Secret handling
//!
//! - The bind password and the new account password are never logged, never placed in an error
//!   string, and never reach a [`SafeDetail`].
//! - The encoded `unicodePwd` value is built in a [`Zeroizing`] buffer. Handing it to `ldap3`
//!   requires a plain `Vec<u8>` copy, and `ldap3` copies it again into its BER encoder; neither
//!   copy is zeroized. The window is a single modify request, but it is a real limitation of the
//!   third-party client rather than something this module can enforce.
//! - Directory-supplied diagnostic text (`LdapResult::text`) and matched DNs are never read into a
//!   detail. Only the numeric LDAP result code is reported.

use std::{collections::HashSet, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, ResultEntry, Scope, SearchEntry,
    result::LdapResult,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject as _},
};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::{
    Integration, IntegrationError, RotateContext, TargetEffect, as_applied, get_cred, optional_cred,
};
use crate::error::{ErrorClass, FailureCode, SafeDetail};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Credential suffix holding the domain controller host name.
const HOST_SUFFIX: &str = "LDAP_HOST";

/// Credential suffix holding the DN of the delegated service account.
const BIND_DN_SUFFIX: &str = "BIND_DN";

/// Credential suffix holding the search base DN for account lookup.
const BASE_DN_SUFFIX: &str = "BASE_DN";

/// Credential suffix holding the delegated service account's password.
///
/// Environment-only; the `[targets]` config section deliberately refuses it.
const BIND_PASSWORD_SUFFIX: &str = "BIND_PASSWORD";

/// Credential suffix holding a path to a PEM file of additional trust anchors.
///
/// Optional. A file path, not a secret, so it may be supplied in the
/// `[targets]` config section as well as in the environment.
const CA_CERTIFICATE_SUFFIX: &str = "CA_CERTIFICATE";

/// The Active Directory attribute holding the account password.
const UNICODE_PWD_ATTR: &[u8] = b"unicodePwd";

/// The "no attributes" OID (RFC 4511 §4.5.1.8) — account lookup needs only the DN.
const NO_ATTRS: [&str; 1] = ["1.1"];

/// Time budget for establishing the TCP + TLS connection to the domain controller.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Time budget for each individual LDAP operation (bind, search, modify).
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// LDAP result codes (RFC 4511 §A.1)
// ---------------------------------------------------------------------------

/// `adminLimitExceeded` — the DC is shedding load.
const RC_ADMIN_LIMIT_EXCEEDED: u32 = 11;

/// `busy` — the DC is temporarily unable to service the request.
const RC_BUSY: u32 = 51;

/// `unavailable` — the DC is shutting down or offline.
const RC_UNAVAILABLE: u32 = 52;

/// `invalidCredentials` — the directory checked the password and it did not match.
const RC_INVALID_CREDENTIALS: u32 = 49;

// ---------------------------------------------------------------------------
// EffectPolicy
// ---------------------------------------------------------------------------

/// How to attribute [`TargetEffect`] for an error raised in a given phase.
///
/// `settled` applies to errors where the outcome of the password write is
/// known — the directory answered, or the failure happened before the write was
/// ever sent. `indeterminate` applies to errors where the write may or may not
/// have been applied, such as a timeout or a dropped connection after the
/// modify request went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EffectPolicy {
    /// Effect for errors whose outcome is known.
    settled: TargetEffect,
    /// Effect for errors whose outcome is not knowable.
    indeterminate: TargetEffect,
}

impl EffectPolicy {
    /// Connect, bind, and account lookup — the password write has not been sent.
    const BEFORE_MODIFY: Self = Self {
        settled: TargetEffect::NotApplied,
        indeterminate: TargetEffect::NotApplied,
    };

    /// The `unicodePwd` write itself.
    ///
    /// A transport failure after the request was flushed leaves the outcome
    /// unknown. `settled` is only the classification default for a
    /// directory-returned error code: because the same password is re-sent on
    /// every retry, a rejection does not on its own prove the credential is
    /// unchanged, so `rotate` replaces it with the answer from
    /// [`settle_rejected_modify`].
    const MODIFY: Self = Self {
        settled: TargetEffect::NotApplied,
        indeterminate: TargetEffect::Unknown,
    };

    /// Everything after a successful password write.
    const AFTER_ROTATION: Self = Self {
        settled: TargetEffect::Applied,
        indeterminate: TargetEffect::Applied,
    };
}

// ---------------------------------------------------------------------------
// ActiveDirectoryIntegration
// ---------------------------------------------------------------------------

/// Active Directory integration driver.
///
/// Holds no credentials: the domain controller host, bind DN, search base and
/// bind password are read out of `ctx.creds` inside each operation, live on the
/// stack for the duration of that operation, and are dropped afterwards.
#[derive(Debug)]
pub(crate) struct ActiveDirectoryIntegration {
    /// Time budget for establishing a connection.
    connect_timeout: Duration,
    /// Time budget for each LDAP operation.
    operation_timeout: Duration,
}

impl ActiveDirectoryIntegration {
    /// Build a driver with the production timeouts.
    pub(crate) fn new() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            operation_timeout: OPERATION_TIMEOUT,
        }
    }

    /// Open an LDAPS connection and start its protocol driver task.
    ///
    /// When `ca_certificate` names a PEM file, the connection trusts the
    /// platform roots plus that file's anchors. When it is `None` the
    /// connection uses the LDAP client's own platform-root configuration,
    /// unchanged.
    async fn connect(
        &self,
        url: &str,
        ca_certificate: Option<&str>,
        policy: EffectPolicy,
    ) -> Result<LdapSession, IntegrationError> {
        let mut settings = LdapConnSettings::new().set_conn_timeout(self.connect_timeout);
        if let Some(path) = ca_certificate {
            settings = settings.set_config(tls_config_with_extra_anchors(path, policy)?);
        }
        let (conn, ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(|e| classify_ldap_error(&e, policy))?;
        let driver = tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        Ok(LdapSession {
            ldap,
            driver,
            operation_timeout: self.operation_timeout,
        })
    }

    /// Open a connection, bind as the delegated service account, and resolve
    /// `account_identity` to a distinguished name.
    async fn open_and_locate(
        &self,
        creds: &Credentials<'_>,
        account_identity: &str,
        policy: EffectPolicy,
    ) -> Result<(LdapSession, String), IntegrationError> {
        let mut session = self
            .connect(&creds.url, creds.ca_certificate, policy)
            .await?;
        session
            .simple_bind(creds.bind_dn, creds.bind_password)
            .await
            .map_err(|e| classify_ldap_error(&e, policy))?;
        let dn = self
            .find_account_dn(&mut session, creds.base_dn, account_identity, policy)
            .await?;
        Ok((session, dn))
    }

    /// Resolve an opaque account identity to the account's distinguished name.
    ///
    /// The identity is matched against `sAMAccountName` and `userPrincipalName`.
    /// The lookup must match exactly one user object: zero matches and multiple
    /// matches are both fatal, because rotating the wrong account is worse than
    /// not rotating at all.
    ///
    /// Only real entries are counted — see [`search_entries_only`] for why the
    /// search result can hold more than the accounts that matched the filter.
    ///
    /// Account state is not consulted. `userAccountControl` is not part of the
    /// filter, so a disabled or locked-out account resolves like any other and
    /// its password is rotated; the rebind in [`Integration::verify`] is then
    /// refused by the directory and the attempt is reported as applied but
    /// unverified.
    async fn find_account_dn(
        &self,
        session: &mut LdapSession,
        base_dn: &str,
        account_identity: &str,
        policy: EffectPolicy,
    ) -> Result<String, IntegrationError> {
        let filter = account_filter(account_identity);
        let search = session
            .ldap
            .with_timeout(self.operation_timeout)
            .search(base_dn, Scope::Subtree, &filter, NO_ATTRS)
            .await
            .map_err(|e| classify_ldap_error(&e, policy))?;
        let (results, _result) = search
            .success()
            .map_err(|e| classify_ldap_error(&e, policy))?;
        let mut entries = search_entries_only(results);

        if entries.len() > 1 {
            return Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: policy.settled,
                code: FailureCode::TargetRejected,
                detail: SafeDetail::from_kind("AmbiguousAccountIdentity"),
            });
        }
        let Some(entry) = entries.pop() else {
            return Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: policy.settled,
                code: FailureCode::TargetRejected,
                detail: SafeDetail::from_kind("AccountNotFound"),
            });
        };

        let dn = SearchEntry::construct(entry).dn;
        if dn.is_empty() {
            return Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: policy.settled,
                code: FailureCode::TargetRejected,
                detail: SafeDetail::from_kind("AccountWithoutDn"),
            });
        }
        Ok(dn)
    }
}

impl Default for ActiveDirectoryIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LdapSession
// ---------------------------------------------------------------------------

/// An open LDAPS connection together with the task driving its protocol loop.
///
/// Dropping the session aborts the driver task, so an early return anywhere in
/// an operation cannot leak a background task or a socket.
struct LdapSession {
    /// Operation handle.
    ldap: Ldap,
    /// The spawned task running [`LdapConnAsync::drive`].
    driver: JoinHandle<()>,
    /// Time budget applied to every operation issued on this connection.
    operation_timeout: Duration,
}

impl LdapSession {
    /// Perform a simple bind, treating any non-zero result code as an error.
    ///
    /// `password` is passed straight to the LDAP client and is never retained.
    async fn simple_bind(&mut self, dn: &str, password: &str) -> Result<(), LdapError> {
        self.ldap
            .with_timeout(self.operation_timeout)
            .simple_bind(dn, password)
            .await?
            .success()?;
        Ok(())
    }

    /// Send an unbind request and drop the session.
    ///
    /// The unbind is bounded like every other operation: the LDAP client
    /// consumes the timeout set for the preceding call, so an unbind left
    /// unbounded waits forever on a domain controller that has stopped reading
    /// its socket. Dropping the session then aborts the driver task and closes
    /// the socket regardless of the unbind's outcome.
    async fn close(mut self) {
        let _ = self
            .ldap
            .with_timeout(self.operation_timeout)
            .unbind()
            .await;
    }
}

impl Drop for LdapSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

// ---------------------------------------------------------------------------
// PasswordWriter
// ---------------------------------------------------------------------------

/// The two directory operations the password write depends on, issued on a
/// connection that is already open, bound, and has located the account.
///
/// [`LdapSession`] is the only production implementation and does nothing but
/// forward to `ldap3`. The trait exists so [`apply_password_write`] — which
/// decides whether a rejected write nonetheless left the account holding the
/// new password — can be exercised without a domain controller.
#[async_trait]
trait PasswordWriter: Send {
    /// Replace `unicodePwd` on `account_dn` with `encoded`.
    ///
    /// A rejection by the directory is carried in the returned [`LdapResult`];
    /// `Err` is reserved for failing to obtain an answer at all.
    async fn replace_password(
        &mut self,
        account_dn: &str,
        encoded: &[u8],
    ) -> Result<LdapResult, LdapError>;

    /// Bind as `account_dn` with `password`, on this same connection.
    async fn bind_as_account(&mut self, account_dn: &str, password: &str) -> Result<(), LdapError>;
}

#[async_trait]
impl PasswordWriter for LdapSession {
    async fn replace_password(
        &mut self,
        account_dn: &str,
        encoded: &[u8],
    ) -> Result<LdapResult, LdapError> {
        let mods = vec![Mod::Replace(
            UNICODE_PWD_ATTR.to_vec(),
            HashSet::from([encoded.to_vec()]),
        )];
        self.ldap
            .with_timeout(self.operation_timeout)
            .modify(account_dn, mods)
            .await
    }

    async fn bind_as_account(&mut self, account_dn: &str, password: &str) -> Result<(), LdapError> {
        self.simple_bind(account_dn, password).await
    }
}

/// Write `new_password` to `account_dn`, and settle what a rejection means for
/// the account's credential.
///
/// An accepted write is the whole answer. A rejection is not self-explanatory —
/// see [`settle_rejected_modify`] — so a rejection that will actually be
/// reported is followed by a rebind as the rotated account with the same
/// password, whose outcome decides the effect. [`probe_settles`] gates that
/// rebind: a rejection the executor is going to retry is left with the phase's
/// indeterminate effect rather than spending an authentication failure against
/// the very account the daemon exists to keep working.
async fn apply_password_write(
    writer: &mut impl PasswordWriter,
    account_dn: &str,
    new_password: &str,
) -> Result<(), IntegrationError> {
    let encoded = encode_unicode_pwd(new_password);
    let answer = writer
        .replace_password(account_dn, &encoded)
        .await
        .map_err(|e| classify_ldap_error(&e, EffectPolicy::MODIFY))?;

    let Err(rejection) = answer.success() else {
        return Ok(());
    };

    let classified = classify_ldap_error(&rejection, EffectPolicy::MODIFY);
    let probe = if probe_settles(&classified) {
        Some(writer.bind_as_account(account_dn, new_password).await)
    } else {
        None
    };
    Err(settle_rejected_modify(classified, probe.as_ref()))
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// The resolved connection parameters for one Active Directory target.
struct Credentials<'a> {
    /// Validated `ldaps://` URL derived from the configured host.
    url: String,
    /// DN of the delegated service account performing the reset.
    bind_dn: &'a str,
    /// Search base for account lookup.
    base_dn: &'a str,
    /// Password of the delegated service account.
    bind_password: &'a str,
    /// Optional path to a PEM file of additional TLS trust anchors.
    ca_certificate: Option<&'a str>,
}

impl<'a> Credentials<'a> {
    /// Read and validate all four required credentials.
    fn resolve(creds: &'a crate::resolver::ResolvedCredentials) -> Result<Self, IntegrationError> {
        let host = get_cred(creds, HOST_SUFFIX)?;
        Ok(Self {
            url: ldaps_url(host)?,
            bind_dn: get_cred(creds, BIND_DN_SUFFIX)?,
            base_dn: get_cred(creds, BASE_DN_SUFFIX)?,
            bind_password: get_cred(creds, BIND_PASSWORD_SUFFIX)?,
            ca_certificate: optional_cred(creds, CA_CERTIFICATE_SUFFIX),
        })
    }
}

// ---------------------------------------------------------------------------
// Integration impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Integration for ActiveDirectoryIntegration {
    /// Replace the account's `unicodePwd` over LDAPS.
    ///
    /// | Failure                          | Effect      | Class     | Code                    |
    /// |----------------------------------|-------------|-----------|-------------------------|
    /// | missing / malformed credential   | NotApplied  | Fatal     | credentials_unresolved  |
    /// | TCP failure, reset connection    | NotApplied  | Transient | target_unreachable      |
    /// | TLS handshake / certificate      | see below   | Fatal     | target_unreachable      |
    /// | bind rejected (rc 49 / 50)       | NotApplied  | Fatal     | target_rejected         |
    /// | account not found / ambiguous    | NotApplied  | Fatal     | target_rejected         |
    /// | modify rejected (rc 13 / 19 / …) | probed      | Fatal     | target_rejected         |
    /// | DC busy or unavailable           | Unknown     | Transient | target_unreachable      |
    /// | timeout after the modify is sent | Unknown     | Transient | target_unreachable      |
    ///
    /// A TLS failure is `NotApplied` before the modify is sent and `Unknown`
    /// after, because TLS can also fail mid-session. It is never transient: an
    /// untrusted chain needs an operator, not a retry.
    ///
    /// "Probed" means the effect is not inferred from the result code but
    /// established by a rebind — see [`settle_rejected_modify`].
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds)?;

        let (mut session, account_dn) = self
            .open_and_locate(&creds, &ctx.account_identity, EffectPolicy::BEFORE_MODIFY)
            .await?;

        apply_password_write(&mut session, &account_dn, &ctx.new_password).await?;

        session.close().await;
        Ok(())
    }

    /// Verify the rotation by binding as the rotated account with the new password.
    ///
    /// A successful simple bind over LDAPS is proof that the directory accepted
    /// the new password: unlike a directory attribute read it cannot be stale,
    /// and unlike a timestamp check it cannot be satisfied by some other write.
    ///
    /// The rebind is issued on the connection the account lookup already
    /// opened, which is left bound as whatever identity it produced and is
    /// closed immediately afterwards.
    ///
    /// Every error carries [`TargetEffect::Applied`] because the password has
    /// already been changed by the time verify runs. A rejected bind is fatal —
    /// retrying it cannot change the answer.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds).map_err(as_applied)?;

        let (mut session, account_dn) = self
            .open_and_locate(&creds, &ctx.account_identity, EffectPolicy::AFTER_ROTATION)
            .await?;
        let bind = session.simple_bind(&account_dn, &ctx.new_password).await;
        session.close().await;

        match bind {
            Ok(()) => Ok(()),
            Err(LdapError::LdapResult { result }) => Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::Applied,
                code: FailureCode::VerificationFailed,
                detail: SafeDetail::from_ldap_result_code(result.rc),
            }),
            Err(other) => Err(classify_ldap_error(&other, EffectPolicy::AFTER_ROTATION)),
        }
    }

    /// Always fails: Active Directory sessions cannot be terminated by an LDAP
    /// password reset.
    ///
    /// Kerberos ticket-granting tickets already issued to the account remain
    /// valid until they expire, and LDAP offers no revocation operation. The
    /// server advertises `supportsSessionTermination: false` for this kind, so
    /// reaching this method means the target system was misconfigured.
    async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::UnsupportedKind,
            detail: SafeDetail::from_kind("ActiveDirectorySessionTerminationUnsupported"),
        })
    }
}

// ---------------------------------------------------------------------------
// Search result filtering
// ---------------------------------------------------------------------------

/// Keep only the `SearchResultEntry` PDUs from a search result.
///
/// `ldap3` returns every PDU the search produced in one `Vec<ResultEntry>`:
/// `SearchResultReference` continuation references and intermediate responses
/// sit alongside the entries that actually matched the filter, distinguished
/// only by [`ResultEntry::is_ref`] and [`ResultEntry::is_intermediate`].
///
/// Active Directory returns a continuation reference for every naming context
/// subordinate to the search base, on every subtree search, whatever the filter
/// matched. A `base_dn` at a domain root therefore always yields references to
/// `DC=DomainDnsZones,…` and `DC=ForestDnsZones,…`. Counting those as matches
/// would report `AmbiguousAccountIdentity` for a correctly configured target,
/// and passing one to [`SearchEntry::construct`] panics, because a reference
/// carries no entry to unwrap. The README recommends an OU-scoped base, but
/// nothing rejects a domain-root one, so the count must be taken over entries.
///
/// References are dropped rather than chased: this daemon rotates only accounts
/// below the configured search base, and following a referral would carry the
/// bind credential to a server the operator never named.
fn search_entries_only(results: Vec<ResultEntry>) -> Vec<ResultEntry> {
    results
        .into_iter()
        .filter(|entry| !entry.is_ref() && !entry.is_intermediate())
        .collect()
}

// ---------------------------------------------------------------------------
// unicodePwd encoding
// ---------------------------------------------------------------------------

/// Encode a password for Active Directory's `unicodePwd` attribute.
///
/// AD requires the value to be the password surrounded by ASCII double quotes
/// and encoded as little-endian UTF-16 with no byte-order mark. A value in any
/// other shape is rejected with `unwillingToPerform`.
///
/// The buffer is [`Zeroizing`], and its capacity is reserved up front so no
/// intermediate reallocation leaves a copy of the password behind.
fn encode_unicode_pwd(password: &str) -> Zeroizing<Vec<u8>> {
    /// UTF-16 code unit for `"`.
    const QUOTE: u16 = b'"' as u16;

    let mut buf = Zeroizing::new(Vec::with_capacity(password.len() * 2 + 4));
    for unit in std::iter::once(QUOTE)
        .chain(password.encode_utf16())
        .chain(std::iter::once(QUOTE))
    {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
    buf
}

// ---------------------------------------------------------------------------
// TLS trust anchors
// ---------------------------------------------------------------------------

/// Build a TLS client configuration trusting the platform roots **plus** the
/// certificates in the PEM file at `path`.
///
/// # Additive, never substitutive
///
/// The file's anchors are appended to the host's native trust store. A domain
/// controller using a private or self-signed certificate becomes reachable
/// without any public CA losing its standing, and without weakening the
/// verification applied to it: the certificate chain and the host name are
/// checked exactly as they are for a publicly-issued certificate.
///
/// # No silent fallback
///
/// Every failure to honour the configured anchor is fatal. A missing file, an
/// unreadable one, a malformed PEM, or a PEM holding no certificate all abort
/// the rotation rather than quietly continuing with platform roots only —
/// falling back would turn a misconfiguration into a connection that the
/// operator believes is pinned but is not.
///
/// The path is reported in no error; only a fixed kind name is.
fn tls_config_with_extra_anchors(
    path: &str,
    policy: EffectPolicy,
) -> Result<Arc<ClientConfig>, IntegrationError> {
    let failure = |kind: &'static str| IntegrationError {
        class: ErrorClass::Fatal,
        effect: policy.settled,
        code: FailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind(kind),
    };

    let roots = root_store_with_extra_anchors(path, policy)?;

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| failure("TlsProviderUnavailable"))?
            .with_root_certificates(roots)
            .with_no_client_auth();

    Ok(Arc::new(config))
}

/// The host's native trust store, as a [`RootCertStore`].
///
/// Certificates the platform offers but rustls cannot add are skipped one by
/// one; the store is never emptied wholesale. This deliberately diverges from
/// the LDAP client's own default configuration, which discards the entire
/// native store when loading it reports any error at all. On a host where that
/// happens, a target naming a `CA_CERTIFICATE` therefore keeps the platform
/// roots while a target without one trusts nothing.
fn platform_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    roots
}

/// [`platform_roots`] plus every certificate in the PEM file at `path`.
///
/// The platform roots are the starting point, so the configured anchors can
/// only widen what is trusted for this one target — they can never remove a
/// public CA or become the sole trust source.
fn root_store_with_extra_anchors(
    path: &str,
    policy: EffectPolicy,
) -> Result<RootCertStore, IntegrationError> {
    let failure = |kind: &'static str| IntegrationError {
        class: ErrorClass::Fatal,
        effect: policy.settled,
        code: FailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind(kind),
    };

    let anchors: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(Path::new(path))
        .map_err(|_| failure("CaCertificateUnreadable"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| failure("CaCertificateInvalid"))?;
    if anchors.is_empty() {
        return Err(failure("CaCertificateEmpty"));
    }

    let mut roots = platform_roots();
    for anchor in anchors {
        roots
            .add(anchor)
            .map_err(|_| failure("CaCertificateInvalid"))?;
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------
// Filter construction
// ---------------------------------------------------------------------------

/// Build the account-lookup filter for an opaque account identity.
///
/// `account_identity` arrives from the server and is attacker-influencable, so
/// it is escaped per RFC 4515 before interpolation. Without escaping, an
/// identity such as `*)(objectClass=` would widen the search and could make it
/// match an account the operator never delegated.
fn account_filter(account_identity: &str) -> String {
    let escaped = escape_filter_value(account_identity);
    format!(
        "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={escaped})(userPrincipalName={escaped})))"
    )
}

/// Escape an assertion value for use inside an LDAP search filter (RFC 4515 §3).
///
/// `*`, `(`, `)`, `\` and NUL must be escaped. Control bytes and all non-ASCII
/// bytes are escaped as well, which keeps multi-byte UTF-8 intact and prevents
/// a hostile identity from smuggling structure into the filter.
fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            b if !(0x20..0x7f).contains(&b) => out.push_str(&format!("\\{b:02x}")),
            b => out.push(b as char),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

/// Build the `ldaps://` URL for a configured domain controller host.
///
/// The host is restricted to the characters that can appear in a host name, an
/// IPv6 literal, or an optional `:port` suffix. Anything else — a scheme, a
/// path, userinfo, whitespace — is refused rather than normalised, so a
/// mistyped host can never silently downgrade the connection or redirect the
/// bind to another server.
fn ldaps_url(host: &str) -> Result<String, IntegrationError> {
    let malformed = || IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: FailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind("MalformedLdapHost"),
    };

    if host.is_empty() {
        return Err(malformed());
    }
    let acceptable = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_'));
    if !acceptable {
        return Err(malformed());
    }

    Ok(format!("ldaps://{host}"))
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Map an [`LdapError`] to an [`IntegrationError`] under the given effect policy.
///
/// Transport-level failures are transient; anything the directory decided —
/// bad credentials, missing rights, schema or policy violations — is fatal,
/// as is a TLS or configuration failure that a retry cannot change.
///
/// Only the LDAP result code and a fixed error-kind name reach the detail. The
/// directory's `diagnosticMessage` and matched DN are never read: both can
/// echo account names and, on some DCs, policy text.
fn classify_ldap_error(err: &LdapError, policy: EffectPolicy) -> IntegrationError {
    match err {
        LdapError::Io { source } if is_tls_error(source) => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.indeterminate,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("TlsHandshakeFailed"),
        },
        LdapError::Io { source } => IntegrationError {
            class: ErrorClass::Transient,
            effect: policy.indeterminate,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind(io_error_kind_name(source.kind())),
        },
        LdapError::Timeout { .. } => IntegrationError {
            class: ErrorClass::Transient,
            effect: policy.indeterminate,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("OperationTimeout"),
        },
        LdapError::EndOfStream
        | LdapError::OpSend { .. }
        | LdapError::ResultRecv { .. }
        | LdapError::IdScrubSend { .. }
        | LdapError::MiscSend { .. } => IntegrationError {
            class: ErrorClass::Transient,
            effect: policy.indeterminate,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("ConnectionClosed"),
        },
        // ldap3 0.12 surfaces TLS failures as `Io` (see `is_tls_error`) and
        // never constructs this variant itself; the arm is a
        // forward-compatibility guard so a future version cannot fall through
        // to `Internal`. Its effect matches the `Io` path for the same reason:
        // TLS can fail mid-session, after a request has been written.
        LdapError::Rustls { .. } => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.indeterminate,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("TlsHandshakeFailed"),
        },
        LdapError::DNSName { .. } => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.settled,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("TlsInvalidServerName"),
        },
        LdapError::UrlParsing { .. }
        | LdapError::UnknownScheme(_)
        | LdapError::EmptyUnixPath
        | LdapError::PortInUnixPath
        | LdapError::MismatchedStreamType => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.settled,
            code: FailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind("MalformedLdapHost"),
        },
        LdapError::LdapResult { result } => classify_result_code(result.rc, policy),
        _ => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.settled,
            code: FailureCode::Internal,
            detail: SafeDetail::from_kind("LdapClientError"),
        },
    }
}

/// Whether rebinding as the account can settle what a rejected `unicodePwd`
/// write did.
///
/// Only a rejection that is actually reported is worth probing. A transient
/// rejection is superseded by the retry that follows it, and the probe is by
/// construction a bind with a password the directory may not hold: one per
/// attempt spends an authentication failure against the managed account on
/// every try, and `badPwdCount` reaching the domain lockout threshold locks
/// out the very account the daemon exists to keep working. An administrative
/// reset does not clear a lockout.
fn probe_settles(classified: &IntegrationError) -> bool {
    classified.class == ErrorClass::Fatal
}

/// Attribute the effect of a rejected `unicodePwd` write.
///
/// A rejection is evidence that *this* request was refused, not that the
/// account still holds its old password. The executor retries `rotate` with
/// the same generated password, so a rejection can follow an earlier attempt
/// whose write did reach the directory and whose outcome was never observed —
/// password-history enforcement then refuses the identical value the second
/// time round with `constraintViolation`. Reporting
/// [`TargetEffect::NotApplied`] on the strength of the result code alone would
/// tell the server the account was untouched while the directory holds a
/// password that never reached the vault.
///
/// `probe` is the outcome of rebinding as the rotated account with the new
/// password, or `None` when [`probe_settles`] declined to spend one; without a
/// probe the outcome is not knowable and the phase's indeterminate effect
/// stands.
fn settle_rejected_modify(
    mut classified: IntegrationError,
    probe: Option<&Result<(), LdapError>>,
) -> IntegrationError {
    classified.effect = match probe {
        Some(probe) => effect_from_probe(probe),
        None => EffectPolicy::MODIFY.indeterminate,
    };
    classified
}

/// Interpret the rebind that [`settle_rejected_modify`] consumes.
///
/// A bind the directory accepted is proof the new password is live. Only
/// `invalidCredentials` is proof it is not: every other result code is the
/// directory declining to answer the credential question — a DC shedding load
/// will very likely shed the probe as well — and a transport failure answers
/// nothing either.
///
/// The residual gap is that a locked-out or disabled account answers
/// `invalidCredentials` whatever password is offered, so the probe reads that
/// state as proof the write did not land.
fn effect_from_probe(probe: &Result<(), LdapError>) -> TargetEffect {
    match probe {
        Ok(()) => TargetEffect::Applied,
        Err(LdapError::LdapResult { result }) if result.rc == RC_INVALID_CREDENTIALS => {
            TargetEffect::NotApplied
        }
        Err(_) => TargetEffect::Unknown,
    }
}

/// Classify a non-zero LDAP result code.
///
/// Load-shedding codes are transient; every other rejection is a decision the
/// directory will repeat, so it is fatal.
fn classify_result_code(rc: u32, policy: EffectPolicy) -> IntegrationError {
    let (class, code) = match rc {
        RC_ADMIN_LIMIT_EXCEEDED | RC_BUSY | RC_UNAVAILABLE => {
            (ErrorClass::Transient, FailureCode::TargetUnreachable)
        }
        _ => (ErrorClass::Fatal, FailureCode::TargetRejected),
    };
    IntegrationError {
        class,
        effect: policy.settled,
        code,
        detail: SafeDetail::from_ldap_result_code(rc),
    }
}

/// Returns `true` when an I/O error is really a TLS failure in disguise.
///
/// `tokio-rustls` reports handshake failures — an untrusted issuer, an expired
/// certificate, a host name that matches no SAN — as
/// `io::Error(InvalidData, rustls::Error)`, and `ldap3` forwards that as
/// [`LdapError::Io`] rather than [`LdapError::Rustls`]. Without this check a
/// rejected certificate would be classified as a transient network fault and
/// retried, when in truth no number of retries will make an untrusted chain
/// verify: it needs an operator to fix the trust configuration.
///
/// TLS can also fail mid-session, after a request has been written, so the
/// caller's `indeterminate` effect applies rather than `settled`.
fn is_tls_error(source: &std::io::Error) -> bool {
    source
        .get_ref()
        .is_some_and(|inner| inner.is::<rustls::Error>())
}

/// Map an [`std::io::ErrorKind`] to a fixed name safe to place in a detail.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ldap3::{
        asn1::{PL, StructureTag, TagClass},
        result::LdapResult,
    };
    use uuid::Uuid;

    use super::*;
    use crate::resolver::ResolvedCredentials;

    /// A password used across leak assertions; must never appear in output.
    const SECRET: &str = "correct-horse-battery-staple";

    fn make_ctx(creds: ResolvedCredentials) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "svc-app".to_string(),
            new_password: Zeroizing::new(SECRET.to_string()),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn ldap_result(rc: u32, text: &str) -> LdapResult {
        LdapResult {
            rc,
            matched: "CN=svc-app,OU=Service Accounts,DC=corp,DC=example".to_string(),
            text: text.to_string(),
            refs: Vec::new(),
            ctrls: Vec::new(),
        }
    }

    /// LDAP protocol-op tag numbers (RFC 4511 §4.5.2, §4.13).
    const TAG_SEARCH_RESULT_ENTRY: u64 = 4;
    const TAG_SEARCH_RESULT_REFERENCE: u64 = 19;
    const TAG_INTERMEDIATE_RESPONSE: u64 = 25;

    /// A `SearchResultEntry` PDU for `dn` with no attributes, shaped the way
    /// [`SearchEntry::construct`] expects: the DN followed by an empty
    /// attribute list.
    fn entry_pdu(dn: &str) -> ResultEntry {
        ResultEntry::new(StructureTag {
            class: TagClass::Application,
            id: TAG_SEARCH_RESULT_ENTRY,
            payload: PL::C(vec![
                StructureTag {
                    class: TagClass::Universal,
                    id: 4,
                    payload: PL::P(dn.as_bytes().to_vec()),
                },
                StructureTag {
                    class: TagClass::Universal,
                    id: 16,
                    payload: PL::C(Vec::new()),
                },
            ]),
        })
    }

    /// A continuation reference of the kind AD returns for a subordinate naming
    /// context under the search base.
    fn reference_pdu(uri: &str) -> ResultEntry {
        ResultEntry::new(StructureTag {
            class: TagClass::Application,
            id: TAG_SEARCH_RESULT_REFERENCE,
            payload: PL::C(vec![StructureTag {
                class: TagClass::Universal,
                id: 4,
                payload: PL::P(uri.as_bytes().to_vec()),
            }]),
        })
    }

    fn intermediate_pdu() -> ResultEntry {
        ResultEntry::new(StructureTag {
            class: TagClass::Application,
            id: TAG_INTERMEDIATE_RESPONSE,
            payload: PL::C(Vec::new()),
        })
    }

    /// The references a domain-root subtree search draws from Active Directory
    /// on every search, whatever the filter matched.
    fn domain_root_references() -> Vec<ResultEntry> {
        vec![
            reference_pdu("ldap://corp.example/DC=DomainDnsZones,DC=corp,DC=example"),
            reference_pdu("ldap://corp.example/DC=ForestDnsZones,DC=corp,DC=example"),
        ]
    }

    // -----------------------------------------------------------------------
    // Search result filtering
    // -----------------------------------------------------------------------

    #[test]
    fn one_match_under_a_domain_root_base_is_not_ambiguous() {
        let mut results = domain_root_references();
        results.insert(
            1,
            entry_pdu("CN=svc-app,OU=Service Accounts,DC=corp,DC=example"),
        );

        let entries = search_entries_only(results);

        assert_eq!(
            entries.len(),
            1,
            "continuation references must not count towards the match count"
        );
        assert_eq!(
            SearchEntry::construct(entries.into_iter().next().expect("one entry")).dn,
            "CN=svc-app,OU=Service Accounts,DC=corp,DC=example"
        );
    }

    #[test]
    fn no_match_under_a_domain_root_base_leaves_nothing_to_construct() {
        let entries = search_entries_only(domain_root_references());

        assert!(
            entries.is_empty(),
            "references alone must resolve to AccountNotFound, never be constructed as an entry"
        );
    }

    #[test]
    fn intermediate_responses_are_dropped_too() {
        let results = vec![
            intermediate_pdu(),
            entry_pdu("CN=svc-app,DC=corp,DC=example"),
        ];

        assert_eq!(search_entries_only(results).len(), 1);
    }

    #[test]
    fn two_real_matches_are_still_ambiguous() {
        let mut results = domain_root_references();
        results.push(entry_pdu("CN=svc-app,OU=A,DC=corp,DC=example"));
        results.push(entry_pdu("CN=svc-app,OU=B,DC=corp,DC=example"));

        assert_eq!(
            search_entries_only(results).len(),
            2,
            "filtering references must not mask a genuinely ambiguous identity"
        );
    }

    // -----------------------------------------------------------------------
    // unicodePwd encoding
    // -----------------------------------------------------------------------

    #[test]
    fn unicode_pwd_is_quoted_utf16le() {
        let encoded = encode_unicode_pwd("Ab1!");
        assert_eq!(
            encoded.as_slice(),
            &[
                0x22, 0x00, // "
                b'A', 0x00, b'b', 0x00, b'1', 0x00, b'!', 0x00, //
                0x22, 0x00, // "
            ]
        );
    }

    #[test]
    fn unicode_pwd_empty_password_is_two_quotes() {
        let encoded = encode_unicode_pwd("");
        assert_eq!(encoded.as_slice(), &[0x22, 0x00, 0x22, 0x00]);
    }

    #[test]
    fn unicode_pwd_encodes_non_bmp_as_surrogate_pair() {
        // U+1F510 CLOSED LOCK WITH KEY → surrogate pair D83D DD10, little-endian.
        let encoded = encode_unicode_pwd("\u{1F510}");
        assert_eq!(
            encoded.as_slice(),
            &[0x22, 0x00, 0x3D, 0xD8, 0x10, 0xDD, 0x22, 0x00]
        );
    }

    #[test]
    fn unicode_pwd_has_no_byte_order_mark() {
        let encoded = encode_unicode_pwd("pw");
        assert_ne!(&encoded[0..2], &[0xFF, 0xFE]);
        assert_ne!(&encoded[0..2], &[0xFE, 0xFF]);
    }

    #[test]
    fn unicode_pwd_never_contains_the_plain_utf8_password() {
        let encoded = encode_unicode_pwd(SECRET);
        assert!(
            encoded
                .windows(SECRET.len())
                .all(|w| w != SECRET.as_bytes()),
            "password must not appear as plain UTF-8"
        );
    }

    // -----------------------------------------------------------------------
    // Filter escaping
    // -----------------------------------------------------------------------

    #[test]
    fn escape_filter_value_escapes_rfc4515_specials() {
        assert_eq!(escape_filter_value("a*b"), "a\\2ab");
        assert_eq!(escape_filter_value("a(b"), "a\\28b");
        assert_eq!(escape_filter_value("a)b"), "a\\29b");
        assert_eq!(escape_filter_value("a\\b"), "a\\5cb");
        assert_eq!(escape_filter_value("a\0b"), "a\\00b");
    }

    #[test]
    fn escape_filter_value_leaves_ordinary_identities_alone() {
        assert_eq!(
            escape_filter_value("svc-app@corp.example"),
            "svc-app@corp.example"
        );
    }

    #[test]
    fn escape_filter_value_escapes_non_ascii_bytes() {
        // "é" is 0xC3 0xA9 in UTF-8.
        assert_eq!(escape_filter_value("é"), "\\c3\\a9");
    }

    #[test]
    fn account_filter_neutralises_hostile_identity() {
        let filter = account_filter("*)(objectClass=*");
        assert!(
            !filter.contains("*)("),
            "filter structure must not be injectable: {filter}"
        );
        assert!(filter.contains("\\2a\\29\\28objectClass=\\2a"));
        assert!(filter.starts_with("(&(objectClass=user)"));
    }

    #[test]
    fn account_filter_matches_sam_and_upn() {
        let filter = account_filter("svc-app");
        assert!(filter.contains("(sAMAccountName=svc-app)"));
        assert!(filter.contains("(userPrincipalName=svc-app)"));
    }

    // -----------------------------------------------------------------------
    // Host validation
    // -----------------------------------------------------------------------

    #[test]
    fn ldaps_url_accepts_hostname() {
        assert_eq!(
            ldaps_url("dc01.corp.example").expect("valid host"),
            "ldaps://dc01.corp.example"
        );
    }

    #[test]
    fn ldaps_url_accepts_explicit_port() {
        assert_eq!(
            ldaps_url("dc01.corp.example:3269").expect("valid host"),
            "ldaps://dc01.corp.example:3269"
        );
    }

    #[test]
    fn ldaps_url_is_always_ldaps() {
        for host in ["dc01.corp.example", "10.0.0.5", "[fe80::1]:636"] {
            let url = ldaps_url(host).expect("valid host");
            assert!(url.starts_with("ldaps://"), "must be LDAPS: {url}");
        }
    }

    #[test]
    fn ldaps_url_rejects_hostile_hosts() {
        for host in [
            "",
            "ldap://dc01.corp.example",
            "dc01.corp.example/path",
            "evil.example@dc01.corp.example",
            "dc01.corp.example?query",
            "dc01 corp example",
            "dc01.corp.example#frag",
        ] {
            match ldaps_url(host) {
                Ok(url) => panic!("host {host:?} must be rejected, produced {url}"),
                Err(err) => {
                    assert_eq!(err.class, ErrorClass::Fatal, "host {host:?}");
                    assert_eq!(
                        err.code,
                        FailureCode::CredentialsUnresolved,
                        "host {host:?}"
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Error classification
    // -----------------------------------------------------------------------

    #[test]
    fn directory_rejections_are_fatal() {
        // 13 confidentialityRequired, 19 constraintViolation, 32 noSuchObject,
        // 49 invalidCredentials, 50 insufficientAccessRights, 53 unwillingToPerform,
        // 16/17/21 schema errors.
        for rc in [13, 16, 17, 19, 21, 32, 49, 50, 53] {
            let err = classify_result_code(rc, EffectPolicy::BEFORE_MODIFY);
            assert_eq!(err.class, ErrorClass::Fatal, "rc {rc} must be fatal");
            assert_eq!(err.code, FailureCode::TargetRejected, "rc {rc}");
            assert_eq!(err.effect, TargetEffect::NotApplied, "rc {rc}");
        }
    }

    #[test]
    fn load_shedding_codes_are_transient() {
        for rc in [RC_ADMIN_LIMIT_EXCEEDED, RC_BUSY, RC_UNAVAILABLE] {
            let err = classify_result_code(rc, EffectPolicy::BEFORE_MODIFY);
            assert_eq!(
                err.class,
                ErrorClass::Transient,
                "rc {rc} must be transient"
            );
            assert_eq!(err.code, FailureCode::TargetUnreachable, "rc {rc}");
        }
    }

    #[test]
    fn network_errors_are_transient() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            },
            EffectPolicy::BEFORE_MODIFY,
        );
        assert_eq!(err.class, ErrorClass::Transient);
        assert_eq!(err.code, FailureCode::TargetUnreachable);
        assert_eq!(err.detail.as_str(), "error kind: ConnectionRefused");
    }

    #[test]
    fn dropped_connection_during_modify_is_unknown_not_not_applied() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            },
            EffectPolicy::MODIFY,
        );
        assert_eq!(
            err.effect,
            TargetEffect::Unknown,
            "a transport failure after the modify is sent leaves the outcome unknown"
        );
    }

    #[test]
    fn directory_rejection_of_the_modify_classifies_as_not_applied() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(19, "constraint violation"),
            },
            EffectPolicy::MODIFY,
        );
        assert_eq!(
            err.effect,
            TargetEffect::NotApplied,
            "the classification default for an answered rejection; rotate then \
             replaces it with the probed effect"
        );
        assert_eq!(err.class, ErrorClass::Fatal);
    }

    #[test]
    fn a_rebind_that_succeeds_proves_the_rejected_write_had_landed() {
        assert_eq!(effect_from_probe(&Ok(())), TargetEffect::Applied);
    }

    #[test]
    fn a_rebind_answered_with_invalid_credentials_proves_the_write_did_not_land() {
        let probe = Err(LdapError::LdapResult {
            result: ldap_result(49, "invalid credentials"),
        });
        assert_eq!(effect_from_probe(&probe), TargetEffect::NotApplied);
    }

    #[test]
    fn a_rebind_the_directory_declined_to_answer_leaves_the_effect_unknown() {
        for rc in [1, 11, 51, 52, 53] {
            let probe = Err(LdapError::LdapResult {
                result: ldap_result(rc, ""),
            });
            assert_eq!(
                effect_from_probe(&probe),
                TargetEffect::Unknown,
                "rc {rc} says nothing about whether the new password is live"
            );
        }
    }

    #[test]
    fn a_rebind_that_cannot_reach_the_directory_leaves_the_effect_unknown() {
        let probe = Err(LdapError::Io {
            source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        });
        assert_eq!(effect_from_probe(&probe), TargetEffect::Unknown);
    }

    fn rejected_modify(rc: u32) -> IntegrationError {
        classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(rc, ""),
            },
            EffectPolicy::MODIFY,
        )
    }

    #[test]
    fn a_transient_rejection_is_not_probed_and_stays_unknown() {
        for rc in [11, 51, 52] {
            let classified = rejected_modify(rc);
            assert!(
                !probe_settles(&classified),
                "rc {rc} is retried, so the probe would only cost a failed bind"
            );
            assert_eq!(
                settle_rejected_modify(classified, None).effect,
                TargetEffect::Unknown
            );
        }
    }

    #[test]
    fn a_rejected_write_the_probe_finds_live_is_reported_as_applied() {
        let settled = settle_rejected_modify(rejected_modify(19), Some(&Ok(())));
        assert_eq!(settled.effect, TargetEffect::Applied);
        assert_eq!(settled.class, ErrorClass::Fatal);
        assert_eq!(settled.code, FailureCode::TargetRejected);
    }

    #[test]
    fn a_rejected_write_the_probe_finds_absent_is_reported_as_not_applied() {
        let classified = rejected_modify(19);
        assert!(probe_settles(&classified));
        let probe = Err(LdapError::LdapResult {
            result: ldap_result(49, ""),
        });
        assert_eq!(
            settle_rejected_modify(classified, Some(&probe)).effect,
            TargetEffect::NotApplied
        );
    }

    #[test]
    fn a_rejected_write_whose_probe_fails_in_transport_is_reported_as_unknown() {
        let probe = Err(LdapError::Io {
            source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        });
        assert_eq!(
            settle_rejected_modify(rejected_modify(19), Some(&probe)).effect,
            TargetEffect::Unknown
        );
    }

    // -----------------------------------------------------------------------
    // The password write and its probe
    // -----------------------------------------------------------------------

    /// The DN the account lookup is taken to have resolved to.
    const ACCOUNT_DN: &str = "CN=svc-app,OU=Managed,DC=corp,DC=example";

    /// A [`PasswordWriter`] that answers from a script and records what it was
    /// asked to do, so a test can assert both the outcome and whether the
    /// rebind probe was issued at all.
    struct FakeDirectory {
        /// The directory's answer to the `unicodePwd` write.
        write: Option<Result<LdapResult, LdapError>>,
        /// The directory's answer to the rebind probe, if one is issued.
        probe: Option<Result<(), LdapError>>,
        /// Each `(dn, value)` the write was asked to send.
        written: Vec<(String, Vec<u8>)>,
        /// Each `(dn, password)` the probe was asked to bind with.
        binds: Vec<(String, String)>,
    }

    impl FakeDirectory {
        /// A directory that answers the write with `write` and refuses to be
        /// probed — any probe fails the test.
        fn answering(write: Result<LdapResult, LdapError>) -> Self {
            Self {
                write: Some(write),
                probe: None,
                written: Vec::new(),
                binds: Vec::new(),
            }
        }

        /// The same, with a scripted answer for the rebind probe.
        fn probed_with(mut self, probe: Result<(), LdapError>) -> Self {
            self.probe = Some(probe);
            self
        }
    }

    #[async_trait]
    impl PasswordWriter for FakeDirectory {
        async fn replace_password(
            &mut self,
            account_dn: &str,
            encoded: &[u8],
        ) -> Result<LdapResult, LdapError> {
            self.written
                .push((account_dn.to_string(), encoded.to_vec()));
            self.write
                .take()
                .expect("the write must be asked for exactly once")
        }

        async fn bind_as_account(
            &mut self,
            account_dn: &str,
            password: &str,
        ) -> Result<(), LdapError> {
            self.binds
                .push((account_dn.to_string(), password.to_string()));
            self.probe
                .take()
                .expect("the probe was issued without a scripted answer")
        }
    }

    #[tokio::test]
    async fn an_accepted_write_succeeds_and_costs_no_bind() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(0, "")));
        apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect("a write the directory accepted must succeed");
        assert!(
            directory.binds.is_empty(),
            "an accepted write settles itself; probing it would spend a bind for nothing"
        );
    }

    #[tokio::test]
    async fn the_write_sends_the_encoded_password_to_the_located_account() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(0, "")));
        apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect("a write the directory accepted must succeed");

        let (dn, value) = directory.written.first().expect("the write must be sent");
        assert_eq!(dn, ACCOUNT_DN, "the write must target the located account");
        assert_eq!(
            value.as_slice(),
            encode_unicode_pwd(SECRET).as_slice(),
            "the value must be the unicodePwd encoding, not the raw password"
        );
        assert!(
            value.windows(SECRET.len()).all(|w| w != SECRET.as_bytes()),
            "the plain password must not be what goes on the wire"
        );
    }

    #[tokio::test]
    async fn a_rejected_write_is_probed_as_the_rotated_account_with_the_new_password() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(19, "constraint violation")))
            .probed_with(Ok(()));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(
            directory.binds,
            vec![(ACCOUNT_DN.to_string(), SECRET.to_string())],
            "the probe must rebind once, as the rotated account, with the new password"
        );
        assert_eq!(
            err.effect,
            TargetEffect::Applied,
            "a probe the directory accepted proves the rejected write had landed"
        );
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.code, FailureCode::TargetRejected);
    }

    #[tokio::test]
    async fn a_rejected_write_whose_probe_is_refused_is_reported_not_applied() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(19, ""))).probed_with(Err(
            LdapError::LdapResult {
                result: ldap_result(RC_INVALID_CREDENTIALS, ""),
            },
        ));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(directory.binds.len(), 1);
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[tokio::test]
    async fn a_rejected_write_whose_probe_cannot_reach_the_directory_is_reported_unknown() {
        let mut directory =
            FakeDirectory::answering(Ok(ldap_result(19, ""))).probed_with(Err(LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            }));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(directory.binds.len(), 1);
        assert_eq!(err.effect, TargetEffect::Unknown);
    }

    #[tokio::test]
    async fn a_transiently_rejected_write_is_never_probed() {
        for rc in [RC_ADMIN_LIMIT_EXCEEDED, RC_BUSY, RC_UNAVAILABLE] {
            let mut directory = FakeDirectory::answering(Ok(ldap_result(rc, "")));

            let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
                .await
                .expect_err("a rejected write must not be reported as success");

            assert!(
                directory.binds.is_empty(),
                "rc {rc} is retried, so probing it would spend a failed bind against \
                 the managed account on every attempt"
            );
            assert_eq!(err.class, ErrorClass::Transient, "rc {rc}");
            assert_eq!(err.effect, TargetEffect::Unknown, "rc {rc}");
        }
    }

    #[tokio::test]
    async fn a_write_that_got_no_answer_is_never_probed_and_stays_unknown() {
        let mut directory = FakeDirectory::answering(Err(LdapError::Io {
            source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        }));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a write that got no answer must not be reported as success");

        assert!(
            directory.binds.is_empty(),
            "the connection carrying the probe is the one that just failed"
        );
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.class, ErrorClass::Transient);
    }

    #[tokio::test]
    async fn a_rejected_write_reports_neither_the_password_nor_directory_text() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(
            53,
            &format!("will not perform for {SECRET}"),
        )))
        .probed_with(Ok(()));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        let rendered = err.to_string();
        assert!(!rendered.contains(SECRET), "password leaked: {rendered}");
        assert!(
            !rendered.contains("OU=Service Accounts"),
            "matched DN leaked: {rendered}"
        );
        assert_eq!(err.detail.as_str(), "LDAP result code 53");
    }

    #[tokio::test(start_paused = true)]
    async fn operation_timeout_during_modify_is_unknown() {
        let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
            .await
            .expect_err("must elapse");
        let err = classify_ldap_error(&LdapError::from(elapsed), EffectPolicy::MODIFY);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.class, ErrorClass::Transient);
        assert_eq!(err.detail.as_str(), "error kind: OperationTimeout");
    }

    #[test]
    fn rejected_certificate_is_fatal_not_transient() {
        let rustls_err = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err),
            },
            EffectPolicy::BEFORE_MODIFY,
        );
        assert_eq!(
            err.class,
            ErrorClass::Fatal,
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
            EffectPolicy::MODIFY,
        );
        assert_eq!(err.effect, TargetEffect::Unknown);
    }

    #[test]
    fn plain_io_errors_stay_transient() {
        let err = classify_ldap_error(
            &LdapError::Io {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not a tls error"),
            },
            EffectPolicy::BEFORE_MODIFY,
        );
        assert_eq!(err.class, ErrorClass::Transient);
    }

    #[test]
    fn tls_failures_are_fatal() {
        let err = classify_ldap_error(
            &LdapError::DNSName {
                source: rustls::pki_types::ServerName::try_from("not a host name")
                    .expect_err("must be invalid"),
            },
            EffectPolicy::BEFORE_MODIFY,
        );
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.detail.as_str(), "error kind: TlsInvalidServerName");
    }

    #[test]
    fn errors_after_rotation_report_applied() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(49, "invalid credentials"),
            },
            EffectPolicy::AFTER_ROTATION,
        );
        assert_eq!(err.effect, TargetEffect::Applied);
    }

    // -----------------------------------------------------------------------
    // Zero-knowledge
    // -----------------------------------------------------------------------

    #[test]
    fn detail_carries_only_the_result_code_not_directory_text() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(53, &format!("rejected password {SECRET}")),
            },
            EffectPolicy::MODIFY,
        );
        assert_eq!(err.detail.as_str(), "LDAP result code 53");
        let rendered = err.to_string();
        assert!(!rendered.contains(SECRET), "password leaked: {rendered}");
        assert!(
            !rendered.contains("OU=Service Accounts"),
            "matched DN leaked: {rendered}"
        );
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
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.code, FailureCode::CredentialsUnresolved);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.detail.as_str(), "error kind: LDAP_HOST");
    }

    #[tokio::test]
    async fn malformed_host_fails_before_connecting() {
        let integration = ActiveDirectoryIntegration::new();
        let mut creds = ResolvedCredentials::new();
        creds.insert(HOST_SUFFIX.to_string(), "ldap://dc01".to_string());
        creds.insert(BIND_DN_SUFFIX.to_string(), "CN=svc,DC=corp".to_string());
        creds.insert(BASE_DN_SUFFIX.to_string(), "DC=corp".to_string());
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), SECRET.to_string());
        let ctx = make_ctx(creds);

        let err = integration
            .rotate(&ctx)
            .await
            .expect_err("a non-LDAPS host must be refused");
        assert_eq!(err.code, FailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: MalformedLdapHost");
        assert!(!err.to_string().contains(SECRET));
    }

    // -----------------------------------------------------------------------
    // TLS trust anchors
    // -----------------------------------------------------------------------

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
    fn extra_anchor_is_added_to_platform_roots_not_substituted() {
        let f = write_temp(TEST_CA_PEM);
        let path = f.path().to_str().expect("utf8 path");

        let baseline = platform_roots().len();
        let widened = root_store_with_extra_anchors(path, EffectPolicy::BEFORE_MODIFY)
            .expect("valid PEM should build a root store")
            .len();

        assert_eq!(
            widened,
            baseline + 1,
            "the anchor must be added to the platform roots, not replace them"
        );
    }

    #[test]
    fn valid_ca_certificate_builds_a_client_config() {
        let f = write_temp(TEST_CA_PEM);
        let path = f.path().to_str().expect("utf8 path");
        assert!(tls_config_with_extra_anchors(path, EffectPolicy::BEFORE_MODIFY).is_ok());
    }

    #[test]
    fn missing_ca_certificate_file_is_fatal() {
        let err = root_store_with_extra_anchors(
            "/nonexistent/path/to/ca-bundle-2f8a1c.pem",
            EffectPolicy::BEFORE_MODIFY,
        )
        .expect_err("a missing PEM must not fall back to platform roots");
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.code, FailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateUnreadable");
    }

    #[test]
    fn malformed_ca_certificate_is_fatal() {
        let truncated = "-----BEGIN CERTIFICATE-----\nMIIDJTCCAg2gAwIBAgIUP9bWk\n";
        let f = write_temp(truncated);
        let path = f.path().to_str().expect("utf8 path");
        let err = root_store_with_extra_anchors(path, EffectPolicy::BEFORE_MODIFY)
            .expect_err("a malformed PEM must not fall back to platform roots");
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateInvalid");
    }

    #[test]
    fn ca_certificate_without_a_certificate_is_fatal() {
        let f = write_temp("# no PEM sections here\n");
        let path = f.path().to_str().expect("utf8 path");
        let err = root_store_with_extra_anchors(path, EffectPolicy::BEFORE_MODIFY)
            .expect_err("a PEM with no certificate must not fall back to platform roots");
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.detail.as_str(), "error kind: CaCertificateEmpty");
    }

    #[test]
    fn ca_certificate_path_never_reaches_the_error_detail() {
        let path = "/etc/secrets/ad-ca-9f3b2e.pem";
        let err = root_store_with_extra_anchors(path, EffectPolicy::BEFORE_MODIFY)
            .expect_err("missing file");
        assert!(
            !err.to_string().contains("9f3b2e"),
            "the configured path must not appear in the error: {err}"
        );
    }

    #[test]
    fn ca_certificate_failure_after_rotation_reports_applied() {
        let err =
            root_store_with_extra_anchors("/nonexistent/ca.pem", EffectPolicy::AFTER_ROTATION)
                .expect_err("missing file");
        assert_eq!(err.effect, TargetEffect::Applied);
    }

    #[test]
    fn ca_certificate_is_optional_and_absent_by_default() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(HOST_SUFFIX.to_string(), "dc01.corp.example".to_string());
        creds.insert(BIND_DN_SUFFIX.to_string(), "CN=svc,DC=corp".to_string());
        creds.insert(BASE_DN_SUFFIX.to_string(), "DC=corp".to_string());
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), SECRET.to_string());

        let resolved = Credentials::resolve(&creds).expect("credentials resolve without a CA");
        assert!(
            resolved.ca_certificate.is_none(),
            "an absent CA_CERTIFICATE must leave the connection on platform roots"
        );
    }

    #[test]
    fn ca_certificate_is_picked_up_when_present() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(HOST_SUFFIX.to_string(), "dc01.corp.example".to_string());
        creds.insert(BIND_DN_SUFFIX.to_string(), "CN=svc,DC=corp".to_string());
        creds.insert(BASE_DN_SUFFIX.to_string(), "DC=corp".to_string());
        creds.insert(BIND_PASSWORD_SUFFIX.to_string(), SECRET.to_string());
        creds.insert(
            CA_CERTIFICATE_SUFFIX.to_string(),
            "/etc/pki/ad-ca.pem".to_string(),
        );

        let resolved = Credentials::resolve(&creds).expect("credentials resolve");
        assert_eq!(resolved.ca_certificate, Some("/etc/pki/ad-ca.pem"));
    }

    // -----------------------------------------------------------------------
    // Session termination
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_sessions_is_unsupported() {
        let integration = ActiveDirectoryIntegration::new();
        let ctx = make_ctx(ResolvedCredentials::new());
        let err = integration
            .terminate_sessions(&ctx)
            .await
            .expect_err("session termination is not supported for Active Directory");
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.code, FailureCode::UnsupportedKind);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(
            err.detail.as_str(),
            "error kind: ActiveDirectorySessionTerminationUnsupported"
        );
    }
}

// ---------------------------------------------------------------------------
// Live domain-controller QA
// ---------------------------------------------------------------------------

/// End-to-end checks against a **real** Active Directory domain controller.
///
/// Every test here is `#[ignore]`d, so `cargo test` — in CI or locally — never
/// opens a connection to a directory. Running them is an explicit act:
///
/// ```text
/// BWRD_AD_LIVE_HOST=dc01.example.com:636 \
/// BWRD_AD_LIVE_BIND_DN='CN=svc-rotate,OU=Service Accounts,DC=example,DC=com' \
/// BWRD_AD_LIVE_BASE_DN='OU=Managed,DC=example,DC=com' \
/// BWRD_AD_LIVE_BIND_PASSWORD='…' \
/// BWRD_AD_LIVE_ACCOUNT='svc-app' \
/// BWRD_AD_LIVE_ACCOUNT_PASSWORD='current password of that account' \
/// BWRD_AD_LIVE_CA=/path/to/dc-ca.pem \
///   cargo test -p bitwarden-rotation-daemon --lib -- --ignored --exact \
///   integrations::active_directory::live::live_rotation_against_a_real_domain_controller
/// ```
///
/// The run **changes the password of `BWRD_AD_LIVE_ACCOUNT`**. Point it only at
/// a disposable account in a test directory.
#[cfg(test)]
mod live {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use chrono::Utc;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::*;
    use crate::resolver::ResolvedCredentials;

    /// Connection parameters for the live directory, read from the environment.
    struct LiveTarget {
        host: String,
        bind_dn: String,
        base_dn: String,
        bind_password: String,
        ca_certificate: Option<String>,
        account: String,
        /// The rotated account's password as it stands before the test runs.
        account_password: String,
    }

    impl LiveTarget {
        /// Read the target from `BWRD_AD_LIVE_*`, or `None` if it is not configured.
        fn from_env() -> Option<Self> {
            let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
            Some(Self {
                host: var("BWRD_AD_LIVE_HOST")?,
                bind_dn: var("BWRD_AD_LIVE_BIND_DN")?,
                base_dn: var("BWRD_AD_LIVE_BASE_DN")?,
                bind_password: var("BWRD_AD_LIVE_BIND_PASSWORD")?,
                ca_certificate: var("BWRD_AD_LIVE_CA"),
                account: var("BWRD_AD_LIVE_ACCOUNT")?,
                account_password: var("BWRD_AD_LIVE_ACCOUNT_PASSWORD")?,
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
                new_password: Zeroizing::new(password.to_string()),
                creds: self.creds(),
                rotation_started_at: Utc::now(),
            }
        }
    }

    /// A `tracing` writer that accumulates everything into a shared buffer.
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

    /// A password that satisfies default AD complexity rules.
    fn generated_password() -> String {
        format!("Bw!{}aQ9", Uuid::new_v4().simple())
    }

    /// Rotate a disposable account, prove the new password works and the old one
    /// does not, and prove neither password reaches the log stream.
    #[tokio::test]
    #[ignore = "requires a live Active Directory domain controller; see the module docs"]
    async fn live_rotation_against_a_real_domain_controller() {
        let target = LiveTarget::from_env()
            .expect("BWRD_AD_LIVE_* environment variables must be set for the live test");

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

        // A password the directory has never held must be rejected. Without this
        // the checks above would also pass against a directory that accepted
        // anything, which would make them meaningless.
        let never_set = generated_password();
        let rejected = integration
            .verify(&target.context(&never_set))
            .await
            .expect_err("a password the account never had must not bind");
        assert_eq!(rejected.class, ErrorClass::Fatal);
        assert_eq!(rejected.code, FailureCode::VerificationFailed);
        assert_eq!(rejected.effect, TargetEffect::Applied);

        // The password the account started with is now two rotations old and
        // must no longer authenticate.
        //
        // Note that the *immediately* preceding password is deliberately not
        // asserted on: Active Directory keeps accepting it for a grace period
        // (`OldPasswordAllowedPeriod`, 60 minutes by default), so a rotation
        // does not revoke the previous credential at once. That is a property
        // of the directory, not of this connector, and it is why the two-step
        // rotation above is needed to make this assertion meaningful.
        let account_password = target.account_password.clone();
        let superseded = integration
            .verify(&target.context(&account_password))
            .await
            .expect_err("the pre-rotation password must no longer bind");
        assert_eq!(superseded.class, ErrorClass::Fatal);
        assert_eq!(superseded.code, FailureCode::VerificationFailed);

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

    /// The connector must refuse a domain controller whose certificate it cannot
    /// chain to a trust anchor, rather than falling back to an unverified connection.
    ///
    /// The detail is asserted first and exactly. Fatal/`NotApplied` alone proves
    /// nothing here: a wrong bind DN (rc 49), a stale base DN (rc 32) and a host
    /// the validator refuses all satisfy those two assertions without a socket
    /// ever being opened, let alone a certificate being rejected.
    ///
    /// The rotation is driven with the account's *current* password rather than
    /// a generated one, so that on a host whose platform trust store already
    /// contains the enterprise root — where the write is expected to succeed and
    /// the assertions below are expected to fail — the fixture account is not
    /// left holding a password the harness discarded.
    #[tokio::test]
    #[ignore = "requires a live Active Directory domain controller; see the module docs"]
    async fn live_rotation_without_the_trust_anchor_is_refused() {
        let mut target = LiveTarget::from_env()
            .expect("BWRD_AD_LIVE_* environment variables must be set for the live test");
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
        assert_eq!(err.code, FailureCode::TargetUnreachable, "error was: {err}");
        assert_eq!(err.class, ErrorClass::Fatal, "error was: {err}");
        assert_eq!(err.effect, TargetEffect::NotApplied, "error was: {err}");
    }
}
