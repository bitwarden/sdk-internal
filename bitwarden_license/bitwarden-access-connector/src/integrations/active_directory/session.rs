use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use bitwarden_pam::RotationFailureCode;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, ResultEntry, Scope, SearchEntry,
    result::LdapResult,
};
use tokio::task::JoinHandle;

use super::{
    Credentials,
    classify::{Phase, classify_ldap_error, target_rejected},
    password_write::PasswordWriter,
    tls::tls_config_with_extra_anchors,
};
use crate::{
    error::{Retry, SafeDetail},
    integrations::{IntegrationError, TargetEffect},
};

/// The account's password. A search never returns it, and replacing it is an administrative reset,
/// which needs the Reset Password right and an encrypted connection. See
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2>.
const UNICODE_PWD_ATTR: &[u8] = b"unicodePwd";

/// The "no attributes" OID (RFC 4511 §4.5.1.8); the lookup only needs the DN.
const NO_ATTRS: [&str; 1] = ["1.1"];

#[derive(Debug, Clone, Copy)]
pub(super) struct Timeouts {
    pub(super) connect: Duration,
    pub(super) operation: Duration,
}

/// An LDAPS connection to a domain controller. Every request on it uses the operation timeout.
pub(super) struct LdapSession {
    ldap: Ldap,
    driver: JoinHandle<()>,
    operation_timeout: Duration,
}

impl LdapSession {
    /// Connects, binds as the delegated service account and resolves `account_identity` to a DN.
    pub(super) async fn open_and_locate(
        creds: &Credentials<'_>,
        account_identity: &str,
        timeouts: Timeouts,
        phase: Phase,
    ) -> Result<(Self, String), IntegrationError> {
        let mut session = Self::connect(&creds.url, creds.ca_certificate, timeouts, phase).await?;
        session
            .simple_bind(creds.bind_dn, creds.bind_password)
            .await
            .map_err(|e| classify_ldap_error(&e, phase))?;
        let dn = session
            .find_account_dn(creds.base_dn, account_identity, phase)
            .await?;
        Ok((session, dn))
    }

    async fn connect(
        url: &str,
        ca_certificate: Option<&str>,
        timeouts: Timeouts,
        phase: Phase,
    ) -> Result<Self, IntegrationError> {
        let mut settings = LdapConnSettings::new().set_conn_timeout(timeouts.connect);
        if let Some(path) = ca_certificate {
            settings = settings.set_config(tls_config_with_extra_anchors(path, phase)?);
        }
        let (conn, ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(|e| classify_ldap_error(&e, phase))?;
        let driver = tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        Ok(Self {
            ldap,
            driver,
            operation_timeout: timeouts.operation,
        })
    }

    /// Exactly one user must match, since rotating the wrong account is worse than not rotating.
    /// Account state isn't checked: a disabled account rotates, and then fails verification.
    async fn find_account_dn(
        &mut self,
        base_dn: &str,
        account_identity: &str,
        phase: Phase,
    ) -> Result<String, IntegrationError> {
        let search = self
            .ldap
            .with_timeout(self.operation_timeout)
            .search(
                base_dn,
                Scope::Subtree,
                &account_filter(account_identity),
                NO_ATTRS,
            )
            .await
            .map_err(|e| classify_ldap_error(&e, phase))?;
        let (results, _result) = search
            .success()
            .map_err(|e| classify_ldap_error(&e, phase))?;
        let mut entries = search_entries_only(results);

        if entries.len() > 1 {
            return Err(target_rejected(phase.settled(), "AmbiguousAccountIdentity"));
        }
        let Some(entry) = entries.pop() else {
            return Err(target_rejected(phase.settled(), "AccountNotFound"));
        };
        let dn = SearchEntry::construct(entry).dn;
        if dn.is_empty() {
            return Err(target_rejected(phase.settled(), "AccountWithoutDn"));
        }
        Ok(dn)
    }

    pub(super) async fn simple_bind(&mut self, dn: &str, password: &str) -> Result<(), LdapError> {
        self.ldap
            .with_timeout(self.operation_timeout)
            .simple_bind(dn, password)
            .await?
            .success()?;
        Ok(())
    }

    /// The unbind is bounded too: unbounded, it waits forever on a DC that stopped reading.
    pub(super) async fn close(mut self) {
        let _ = self
            .ldap
            .with_timeout(self.operation_timeout)
            .unbind()
            .await;
    }
}

impl Drop for LdapSession {
    fn drop(&mut self) {
        // Closes the socket, so an early return can't leak it.
        self.driver.abort();
    }
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

/// AD answers every subtree search with continuation references to subordinate naming contexts,
/// so a domain-root base would look ambiguous, and `SearchEntry::construct` panics on a reference.
/// References are dropped rather than chased, so the bind never goes to a server nobody named.
fn search_entries_only(results: Vec<ResultEntry>) -> Vec<ResultEntry> {
    results
        .into_iter()
        .filter(|entry| !entry.is_ref() && !entry.is_intermediate())
        .collect()
}

/// The identity comes from the server, so it is escaped before it goes into the filter.
fn account_filter(account_identity: &str) -> String {
    let escaped = escape_filter_value(account_identity);
    format!(
        "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={escaped})(userPrincipalName={escaped})))"
    )
}

/// RFC 4515 §3, plus control and non-ASCII bytes.
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

/// Refuses anything beyond a host name, IPv6 literal and `:port` rather than normalising it, so a
/// typo can't downgrade the connection or send the bind elsewhere.
pub(super) fn ldaps_url(host: &str) -> Result<String, IntegrationError> {
    let acceptable = !host.is_empty()
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        });
    if !acceptable {
        return Err(IntegrationError::new(
            Retry::Permanent,
            TargetEffect::NotApplied,
            RotationFailureCode::CredentialsUnresolved,
            SafeDetail::from_kind("MalformedLdapHost"),
        ));
    }
    Ok(format!("ldaps://{host}"))
}

#[cfg(test)]
mod tests {
    use ldap3::asn1::{PL, StructureTag, TagClass};

    use super::*;

    // LDAP protocol-op tags, RFC 4511 §4.5.2 and §4.13.
    const TAG_SEARCH_RESULT_ENTRY: u64 = 4;
    const TAG_SEARCH_RESULT_REFERENCE: u64 = 19;
    const TAG_INTERMEDIATE_RESPONSE: u64 = 25;

    /// The DN followed by an empty attribute list, as `SearchEntry::construct` expects.
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

    /// What AD returns for a domain-root subtree search, whatever the filter matched.
    fn domain_root_references() -> Vec<ResultEntry> {
        vec![
            reference_pdu("ldap://corp.example/DC=DomainDnsZones,DC=corp,DC=example"),
            reference_pdu("ldap://corp.example/DC=ForestDnsZones,DC=corp,DC=example"),
        ]
    }

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
                    assert_eq!(err.retry, Retry::Permanent, "host {host:?}");
                    assert_eq!(
                        err.code,
                        RotationFailureCode::CredentialsUnresolved,
                        "host {host:?}"
                    );
                }
            }
        }
    }
}
