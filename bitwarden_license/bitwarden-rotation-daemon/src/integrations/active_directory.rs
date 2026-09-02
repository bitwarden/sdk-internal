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
//! The server certificate is validated against the host's native trust store,
//! so the issuing enterprise CA must be trusted by the machine running the
//! daemon.
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

use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use bitwarden_sensitive_value::ExposeSensitive as _;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, ResultEntry, Scope, SearchEntry,
};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::{Integration, IntegrationError, RotateContext, TargetEffect};
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
    /// A directory-returned error code means the write was rejected, so the
    /// credential is unchanged. A transport failure after the request was
    /// flushed leaves the outcome unknown.
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
    async fn connect(
        &self,
        url: &str,
        policy: EffectPolicy,
    ) -> Result<LdapSession, IntegrationError> {
        let settings = LdapConnSettings::new().set_conn_timeout(self.connect_timeout);
        let (conn, ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(|e| classify_ldap_error(&e, policy))?;
        let driver = tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        Ok(LdapSession { ldap, driver })
    }

    /// Open a connection, bind as the delegated service account, and resolve
    /// `account_identity` to a distinguished name.
    async fn open_and_locate(
        &self,
        creds: &Credentials<'_>,
        account_identity: &str,
        policy: EffectPolicy,
    ) -> Result<(LdapSession, String), IntegrationError> {
        let mut session = self.connect(&creds.url, policy).await?;
        session
            .simple_bind(creds.bind_dn, creds.bind_password, self.operation_timeout)
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
    /// The lookup must match exactly one enabled user object: zero matches and
    /// multiple matches are both fatal, because rotating the wrong account is
    /// worse than not rotating at all.
    ///
    /// Only real entries are counted — see [`search_entries_only`] for why the
    /// search result can hold more than the accounts that matched the filter.
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
}

impl LdapSession {
    /// Perform a simple bind, treating any non-zero result code as an error.
    ///
    /// `password` is passed straight to the LDAP client and is never retained.
    async fn simple_bind(
        &mut self,
        dn: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<(), LdapError> {
        self.ldap
            .with_timeout(timeout)
            .simple_bind(dn, password)
            .await?
            .success()?;
        Ok(())
    }

    /// Send an unbind request and drop the session.
    async fn close(mut self) {
        let _ = self.ldap.unbind().await;
    }
}

impl Drop for LdapSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
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
    /// | Failure                          | Effect     | Class     | Code                     |
    /// |----------------------------------|------------|-----------|--------------------------|
    /// | missing / malformed credential   | NotApplied | Fatal     | credentials_unresolved   |
    /// | TCP or TLS failure               | NotApplied | Transient | target_unreachable       |
    /// | certificate rejected             | NotApplied | Fatal     | target_unreachable       |
    /// | bind rejected (rc 49 / 50)       | NotApplied | Fatal     | target_rejected          |
    /// | account not found / ambiguous    | NotApplied | Fatal     | target_rejected          |
    /// | modify rejected (rc 13 / 19 / …) | NotApplied | Fatal     | target_rejected          |
    /// | DC busy or unavailable           | NotApplied | Transient | target_unreachable       |
    /// | timeout after the modify is sent | Unknown    | Transient | target_unreachable       |
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds)?;

        let (mut session, account_dn) = self
            .open_and_locate(&creds, &ctx.account_identity, EffectPolicy::BEFORE_MODIFY)
            .await?;

        let encoded = encode_unicode_pwd(&ctx.new_password);
        let mods = vec![Mod::Replace(
            UNICODE_PWD_ATTR.to_vec(),
            HashSet::from([encoded.to_vec()]),
        )];

        let result = session
            .ldap
            .with_timeout(self.operation_timeout)
            .modify(&account_dn, mods)
            .await
            .map_err(|e| classify_ldap_error(&e, EffectPolicy::MODIFY))?;
        result
            .success()
            .map_err(|e| classify_ldap_error(&e, EffectPolicy::MODIFY))?;

        session.close().await;
        Ok(())
    }

    /// Verify the rotation by binding as the rotated account with the new password.
    ///
    /// A successful simple bind over LDAPS is proof that the directory accepted
    /// the new password: unlike a directory attribute read it cannot be stale,
    /// and unlike a timestamp check it cannot be satisfied by some other write.
    ///
    /// Every error carries [`TargetEffect::Applied`] because the password has
    /// already been changed by the time verify runs. A rejected bind is fatal —
    /// retrying it cannot change the answer.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let creds = Credentials::resolve(&ctx.creds).map_err(as_applied)?;

        let (lookup, account_dn) = self
            .open_and_locate(&creds, &ctx.account_identity, EffectPolicy::AFTER_ROTATION)
            .await?;
        lookup.close().await;

        let mut session = self
            .connect(&creds.url, EffectPolicy::AFTER_ROTATION)
            .await?;
        let bind = session
            .simple_bind(&account_dn, &ctx.new_password, self.operation_timeout)
            .await;
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
        LdapError::Rustls { .. } => IntegrationError {
            class: ErrorClass::Fatal,
            effect: policy.settled,
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

/// Re-attribute an error to [`TargetEffect::Applied`].
///
/// Used in `verify`, where helpers that default to `NotApplied` are called
/// after the password has already been changed.
fn as_applied(mut err: IntegrationError) -> IntegrationError {
    err.effect = TargetEffect::Applied;
    err
}

// ---------------------------------------------------------------------------
// Credential lookup helper
// ---------------------------------------------------------------------------

/// Look up a required credential suffix, returning
/// `Fatal/NotApplied/credentials_unresolved` if absent.
///
/// The error detail names only the missing **suffix**, never a value.
fn get_cred<'a>(
    creds: &'a crate::resolver::ResolvedCredentials,
    suffix: &'static str,
) -> Result<&'a str, IntegrationError> {
    creds
        .get(suffix)
        .map(|s| s.expose().as_ref() as &str)
        .ok_or_else(|| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind(suffix),
        })
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
    fn directory_rejection_of_the_modify_is_not_applied() {
        let err = classify_ldap_error(
            &LdapError::LdapResult {
                result: ldap_result(19, "constraint violation"),
            },
            EffectPolicy::MODIFY,
        );
        assert_eq!(
            err.effect,
            TargetEffect::NotApplied,
            "an answered rejection means the credential is unchanged"
        );
        assert_eq!(err.class, ErrorClass::Fatal);
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
