//! Passkey opportunity detection.
//!
//! Port of the web vault's passkey report logic (`PasskeyReportService` in
//! `apps/web/src/app/dirt/reports/pages/passkey-report.service.ts`). Given lightweight
//! descriptions of the user's ciphers and the passkey directory (served by
//! `GET /reports/passkey-directory`), determine which login ciphers belong to sites that support
//! signing in with a passkey and/or using a passkey as a second factor.
//!
//! This module is pure logic: it performs no network requests and no decryption.

use std::collections::HashMap;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{CipherId, CipherType};

/// A single entry from the passkey directory.
///
/// Mirrors `PasskeyDirectoryEntryResponse` in the TypeScript clients. Use the
/// `From<PasskeyDirectoryResponseModel>` conversion when the directory was fetched with the
/// generated API client.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct PasskeyDirectoryEntry {
    /// The domain (or host) of the site, e.g. `example.com`. Entries without a domain are ignored.
    #[serde(default)]
    pub domain_name: Option<String>,
    /// URL of the site's passkey setup instructions, if any.
    #[serde(default)]
    pub instructions: Option<String>,
    /// Whether the site supports passwordless sign-in with a passkey.
    #[serde(default)]
    pub supports_passkey_login: bool,
    /// Whether the site supports a passkey as a second factor (MFA).
    #[serde(default)]
    pub supports_passkey_mfa: bool,
}

impl From<bitwarden_api_api::models::PasskeyDirectoryResponseModel> for PasskeyDirectoryEntry {
    fn from(model: bitwarden_api_api::models::PasskeyDirectoryResponseModel) -> Self {
        // Matches `PasskeyDirectoryEntryResponse`: missing flags default to `false`.
        Self {
            domain_name: model.domain_name,
            instructions: model.instructions,
            supports_passkey_login: model.passwordless.unwrap_or(false),
            supports_passkey_mfa: model.mfa.unwrap_or(false),
        }
    }
}

/// The subset of a decrypted cipher needed to evaluate it for passkey opportunities.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCandidate {
    /// Cipher ID, echoed back in the matching [`PasskeyOpportunity`].
    pub id: CipherId,
    /// Cipher type. Only [`CipherType::Login`] ciphers are eligible.
    pub r#type: CipherType,
    /// The login's URIs, in the cipher's order. Empty strings are skipped. Omit absent (null)
    /// URIs; doing so does not change the result.
    pub uris: Vec<String>,
    /// Whether the login already has a FIDO2 credential (passkey) stored.
    pub has_fido2_credentials: bool,
    /// Whether the cipher is in the trash.
    pub is_deleted: bool,
    /// Whether the user is permitted to view the cipher's password (`CipherView::view_password`).
    pub view_password: bool,
}

/// A cipher for which the passkey directory lists passkey support.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct PasskeyOpportunity {
    /// ID of the matching [`PasskeyCandidate`].
    pub id: CipherId,
    /// Whether the site supports passwordless sign-in with a passkey.
    pub supports_passkey_login: bool,
    /// Whether the site supports a passkey as a second factor (MFA).
    pub supports_passkey_mfa: bool,
    /// URL of the site's passkey setup instructions. `None` when the directory entry has no
    /// instructions or an empty string.
    pub instructions: Option<String>,
}

/// Domain-keyed lookup built from the passkey directory.
pub(super) struct PasskeyDirectory<'a> {
    entries: HashMap<&'a str, &'a PasskeyDirectoryEntry>,
}

impl<'a> PasskeyDirectory<'a> {
    /// Build the lookup. Entries without a domain are skipped. When several entries share a
    /// domain, the last one wins (same as `Map.set` in the web vault).
    pub(super) fn new(entries: &'a [PasskeyDirectoryEntry]) -> Self {
        let entries = entries
            .iter()
            .filter_map(|e| e.domain_name.as_deref().map(|d| (d, e)))
            .collect();
        Self { entries }
    }

    fn get(&self, key: &str) -> Option<&'a PasskeyDirectoryEntry> {
        self.entries.get(key).copied()
    }

    /// Find the directory entry for a candidate, or `None` when the candidate is not eligible or
    /// no URI matches. Mirrors `PasskeyReportService.getPasskeyServiceMatch`.
    pub(super) fn find_match(
        &self,
        candidate: &PasskeyCandidate,
    ) -> Option<&'a PasskeyDirectoryEntry> {
        if candidate.r#type != CipherType::Login
            || candidate.uris.is_empty()
            || candidate.has_fido2_credentials
            || candidate.is_deleted
            || !candidate.view_password
        {
            return None;
        }

        candidate
            .uris
            .iter()
            .filter(|uri| !uri.is_empty())
            .find_map(|uri| {
                // The web vault replaces the first "www." anywhere in the string, case-sensitive
                // (`String.prototype.replace` with a string pattern). Kept as-is for parity.
                let uri = uri.replacen("www.", "", 1);
                [get_host(&uri), get_domain(&uri)]
                    .into_iter()
                    .flatten()
                    .find_map(|key| self.get(&key))
            })
    }

    /// Evaluate a candidate and build its opportunity, if any.
    /// Mirrors `PasskeyReportService.evaluateCipher` / `buildPasskeyCipherRow`.
    pub(super) fn evaluate(&self, candidate: &PasskeyCandidate) -> Option<PasskeyOpportunity> {
        self.find_match(candidate).map(|entry| PasskeyOpportunity {
            id: candidate.id,
            supports_passkey_login: entry.supports_passkey_login,
            supports_passkey_mfa: entry.supports_passkey_mfa,
            // `match.instructions || undefined`: empty string becomes absent.
            instructions: entry.instructions.clone().filter(|i| !i.is_empty()),
        })
    }
}

/// Return the opportunities for `candidates`, in input order. Candidates that are not eligible
/// or do not match are omitted. Mirrors `PasskeyReportService.processCiphers`.
pub(super) fn find_passkey_opportunities(
    candidates: &[PasskeyCandidate],
    directory: &[PasskeyDirectoryEntry],
) -> Vec<PasskeyOpportunity> {
    let directory = PasskeyDirectory::new(directory);
    candidates
        .iter()
        .filter_map(|c| directory.evaluate(c))
        .collect()
}

/// Parse a URI the way `Utils.getUrl` does: trim, assume `http://` when there is no scheme but
/// the string contains a dot, and give up otherwise.
fn parse_url(uri: &str) -> Option<Url> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }
    if uri.contains("://") {
        Url::parse(uri).ok()
    } else if uri.contains('.') {
        Url::parse(&format!("http://{uri}")).ok()
    } else {
        None
    }
}

/// Port of `Utils.getHost`: the WHATWG URL `host`, which includes a non-default port
/// (e.g. `example.com:8443`).
fn get_host(uri: &str) -> Option<String> {
    let url = parse_url(uri)?;
    let host = url.host_str().filter(|h| !h.is_empty())?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Port of `Utils.getDomain`: the registrable domain of the URI's hostname, or the hostname
/// itself for `localhost` and IP addresses.
fn get_domain(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if uri.is_empty() || uri.starts_with("data:") || uri.starts_with("about:") {
        return None;
    }
    // tldts accepts bare hostnames (including dotless ones like `localhost`), so always fall back
    // to an `http://` prefix rather than requiring a dot like `Utils.getUrl` does.
    let url = if uri.contains("://") {
        Url::parse(uri).ok()?
    } else {
        Url::parse(&format!("http://{uri}")).ok()?
    };

    let host = url.host_str().filter(|h| !h.is_empty())?;
    // IPv6 hosts are bracketed in URLs; tldts reports the bare address.
    if let Some(ipv6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return Some(ipv6.to_owned());
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_owned());
    }
    // tldts lowercases the hostname; the URL parser only does so for special schemes.
    let hostname = host.to_ascii_lowercase();
    if hostname == "localhost" {
        return Some(hostname);
    }
    registrable_domain(&hostname)
}

/// Registrable domain ("eTLD+1") of a lowercase hostname.
///
/// The web vault uses tldts with the full Public Suffix List (ICANN and private sections). The SDK
/// does not currently ship a PSL, so this approximation treats the last label as the public
/// suffix. That gives the same result as tldts whenever the public suffix is a single label
/// (`.com`, `.org`, `.app`, unknown TLDs, ...) and differs for multi-label suffixes such as
/// `co.uk` or private suffixes such as `github.io`.
// TODO: replace with a Public Suffix List lookup once a PSL dependency is approved.
fn registrable_domain(hostname: &str) -> Option<String> {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    let mut labels = hostname.rsplit('.');
    let tld = labels.next().filter(|l| !l.is_empty())?;
    let sld = labels.next().filter(|l| !l.is_empty())?;
    Some(format!("{sld}.{tld}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str, instructions: &str, login: bool, mfa: bool) -> PasskeyDirectoryEntry {
        PasskeyDirectoryEntry {
            domain_name: Some(domain.to_owned()),
            instructions: Some(instructions.to_owned()),
            supports_passkey_login: login,
            supports_passkey_mfa: mfa,
        }
    }

    /// Same fixture as the web spec's `passkeyServices`.
    fn directory() -> Vec<PasskeyDirectoryEntry> {
        vec![
            entry("example.com", "https://example.com/setup", true, false),
            entry("test.com", "", false, true),
        ]
    }

    fn id(n: u128) -> CipherId {
        CipherId::new(uuid::Uuid::from_u128(n))
    }

    /// Same defaults as the web spec's `createCipherView`.
    fn candidate(n: u128, uris: &[&str]) -> PasskeyCandidate {
        PasskeyCandidate {
            id: id(n),
            r#type: CipherType::Login,
            uris: uris.iter().map(|u| u.to_string()).collect(),
            has_fido2_credentials: false,
            is_deleted: false,
            view_password: true,
        }
    }

    fn find_match(c: &PasskeyCandidate, dir: &[PasskeyDirectoryEntry]) -> Option<String> {
        PasskeyDirectory::new(dir)
            .find_match(c)
            .and_then(|e| e.domain_name.clone())
    }

    // --- loadPasskeyDirectory ---

    #[test]
    fn directory_builds_lookup_from_entries() {
        let dir = directory();
        let lookup = PasskeyDirectory::new(&dir);
        assert_eq!(lookup.entries.len(), 2);
        assert!(lookup.get("example.com").unwrap().supports_passkey_login);
        assert!(lookup.get("test.com").unwrap().supports_passkey_mfa);
    }

    #[test]
    fn directory_skips_entries_without_domain() {
        let dir = vec![
            entry("example.com", "https://example.com/setup", true, false),
            PasskeyDirectoryEntry {
                domain_name: None,
                instructions: Some(String::new()),
                supports_passkey_login: false,
                supports_passkey_mfa: true,
            },
        ];
        let lookup = PasskeyDirectory::new(&dir);
        assert_eq!(lookup.entries.len(), 1);
        assert!(lookup.get("example.com").is_some());
    }

    #[test]
    fn directory_empty() {
        assert!(PasskeyDirectory::new(&[]).entries.is_empty());
    }

    #[test]
    fn directory_last_duplicate_domain_wins() {
        let dir = vec![
            entry("example.com", "first", true, false),
            entry("example.com", "second", false, true),
        ];
        let lookup = PasskeyDirectory::new(&dir);
        assert_eq!(
            lookup.get("example.com").unwrap().instructions.as_deref(),
            Some("second")
        );
    }

    #[test]
    fn directory_entry_from_api_model_defaults_flags_to_false() {
        let model = bitwarden_api_api::models::PasskeyDirectoryResponseModel {
            domain_name: Some("example.com".to_owned()),
            passwordless: None,
            mfa: Some(true),
            instructions: None,
        };
        assert_eq!(
            PasskeyDirectoryEntry::from(model),
            PasskeyDirectoryEntry {
                domain_name: Some("example.com".to_owned()),
                instructions: None,
                supports_passkey_login: false,
                supports_passkey_mfa: true,
            }
        );
    }

    #[test]
    fn directory_entry_deserializes_camel_case() {
        let json = r#"{"domainName":"example.com","instructions":"x","supportsPasskeyLogin":true}"#;
        let e: PasskeyDirectoryEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.domain_name.as_deref(), Some("example.com"));
        assert!(e.supports_passkey_login);
        assert!(!e.supports_passkey_mfa);
    }

    // --- processCiphers ---

    #[test]
    fn process_returns_rows_for_matching_ciphers() {
        let candidates = vec![
            candidate(1, &["https://example.com"]),
            candidate(2, &["https://nomatch.com"]),
        ];
        let rows = find_passkey_opportunities(&candidates, &directory());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id(1));
    }

    #[test]
    fn process_returns_empty_when_no_ciphers_match() {
        let rows =
            find_passkey_opportunities(&[candidate(1, &["https://nomatch.com"])], &directory());
        assert!(rows.is_empty());
    }

    #[test]
    fn process_returns_empty_with_empty_directory() {
        let rows = find_passkey_opportunities(&[candidate(1, &["https://example.com"])], &[]);
        assert!(rows.is_empty());
    }

    #[test]
    fn process_preserves_input_order() {
        let candidates = vec![
            candidate(3, &["https://test.com"]),
            candidate(1, &["https://example.com"]),
            candidate(2, &["https://test.com"]),
        ];
        let ids: Vec<_> = find_passkey_opportunities(&candidates, &directory())
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, vec![id(3), id(1), id(2)]);
    }

    // --- getPasskeyServiceMatch ---

    #[test]
    fn match_for_matching_cipher() {
        let dir = directory();
        let m = PasskeyDirectory::new(&dir)
            .find_match(&candidate(1, &["https://example.com"]))
            .unwrap();
        assert_eq!(m.instructions.as_deref(), Some("https://example.com/setup"));
    }

    #[test]
    fn no_match_for_non_login() {
        for t in [
            CipherType::SecureNote,
            CipherType::Card,
            CipherType::Identity,
            CipherType::SshKey,
        ] {
            let c = PasskeyCandidate {
                r#type: t,
                ..candidate(1, &["https://example.com"])
            };
            assert_eq!(find_match(&c, &directory()), None, "{t:?}");
        }
    }

    #[test]
    fn no_match_without_uris() {
        assert_eq!(find_match(&candidate(1, &[]), &directory()), None);
    }

    #[test]
    fn no_match_with_fido2_credentials() {
        let c = PasskeyCandidate {
            has_fido2_credentials: true,
            ..candidate(1, &["https://example.com"])
        };
        assert_eq!(find_match(&c, &directory()), None);
    }

    #[test]
    fn no_match_when_deleted() {
        let c = PasskeyCandidate {
            is_deleted: true,
            ..candidate(1, &["https://example.com"])
        };
        assert_eq!(find_match(&c, &directory()), None);
    }

    #[test]
    fn no_match_without_view_password() {
        let c = PasskeyCandidate {
            view_password: false,
            ..candidate(1, &["https://example.com"])
        };
        assert_eq!(find_match(&c, &directory()), None);
    }

    #[test]
    fn match_with_www_stripped() {
        let c = candidate(1, &["https://www.example.com/login"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("example.com"));
    }

    #[test]
    fn match_if_any_uri_matches() {
        let c = candidate(1, &["https://nomatch.com", "https://example.com/dashboard"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("example.com"));
    }

    #[test]
    fn match_skips_empty_and_whitespace_uris() {
        let c = candidate(1, &["", "   ", "https://example.com"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("example.com"));
    }

    #[test]
    fn no_match_for_non_matching_uris() {
        assert_eq!(
            find_match(&candidate(1, &["https://nomatch.com"]), &directory()),
            None
        );
    }

    #[test]
    fn first_matching_uri_wins() {
        let c = candidate(1, &["https://test.com", "https://example.com"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("test.com"));
    }

    #[test]
    fn host_is_preferred_over_domain() {
        let dir = vec![
            entry("example.com", "domain", true, false),
            entry("accounts.example.com", "host", false, true),
        ];
        let c = candidate(1, &["https://accounts.example.com/login"]);
        assert_eq!(
            find_match(&c, &dir).as_deref(),
            Some("accounts.example.com")
        );
    }

    #[test]
    fn subdomain_falls_back_to_registrable_domain() {
        let c = candidate(1, &["https://login.example.com/path"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("example.com"));
    }

    #[test]
    fn intermediate_subdomain_entry_does_not_match_deeper_host() {
        // Neither the host nor the registrable domain equals the entry, so no match.
        let dir = vec![entry("aws.amazon.com", "", true, false)];
        let c = candidate(1, &["https://console.aws.amazon.com"]);
        assert_eq!(find_match(&c, &dir), None);
    }

    #[test]
    fn uri_without_scheme_matches() {
        assert_eq!(
            find_match(&candidate(1, &["example.com"]), &directory()).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            find_match(&candidate(1, &["www.example.com/login"]), &directory()).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn host_is_case_insensitive_but_directory_keys_are_not() {
        let c = candidate(1, &["https://EXAMPLE.com"]);
        assert_eq!(find_match(&c, &directory()).as_deref(), Some("example.com"));
        let dir = vec![entry("Example.com", "", true, false)];
        assert_eq!(
            find_match(&candidate(1, &["https://example.com"]), &dir),
            None
        );
    }

    #[test]
    fn non_default_port_matches_via_domain_only() {
        // `getHost` returns "example.com:8443", which is not a directory key; `getDomain` matches.
        let dir = vec![entry("example.com:8443", "host", true, false)];
        assert_eq!(
            find_match(&candidate(1, &["https://example.com:8443"]), &dir).as_deref(),
            Some("example.com:8443")
        );
        assert_eq!(
            find_match(&candidate(1, &["https://example.com:8443"]), &directory()).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn data_and_about_uris_never_match() {
        for uri in ["data:text/plain,example.com", "about:blank"] {
            assert_eq!(
                find_match(&candidate(1, &[uri]), &directory()),
                None,
                "{uri}"
            );
        }
    }

    #[test]
    fn ip_and_localhost_match_by_hostname() {
        let dir = vec![
            entry("192.168.1.1", "", true, false),
            entry("localhost", "", true, false),
        ];
        assert!(find_match(&candidate(1, &["http://192.168.1.1/x"]), &dir).is_some());
        assert!(find_match(&candidate(1, &["http://localhost:8080"]), &dir).is_some());
        // IPv6: the host step yields "[::1]", the domain step the bare address.
        let dir = vec![entry("::1", "", true, false)];
        assert!(find_match(&candidate(1, &["http://[::1]/"]), &dir).is_some());
        let dir = vec![
            entry("192.168.1.1", "", true, false),
            entry("localhost", "", true, false),
        ];
        // Bare `localhost` has no dot, so getHost is null, but getDomain still returns it.
        assert!(find_match(&candidate(1, &["localhost"]), &dir).is_some());
    }

    // --- Quirks inherited from the web vault, pinned so they are changed deliberately ---

    #[test]
    fn quirk_www_is_replaced_anywhere_not_just_as_prefix() {
        // "awww.example.com" becomes "aexample.com".
        let dir = vec![entry("aexample.com", "", true, false)];
        assert!(find_match(&candidate(1, &["https://awww.example.com"]), &dir).is_some());
    }

    #[test]
    fn quirk_www_replacement_is_case_sensitive() {
        // "WWW." is not stripped, so the host step misses, but the domain step still matches.
        let dir = vec![entry("example.com", "", true, false)];
        assert!(find_match(&candidate(1, &["https://WWW.example.com"]), &dir).is_some());
        let dir = vec![entry("sub.example.com", "", true, false)];
        assert!(find_match(&candidate(1, &["https://WWW.sub.example.com"]), &dir).is_none());
        assert!(find_match(&candidate(1, &["https://www.sub.example.com"]), &dir).is_some());
    }

    // --- Registrable-domain differences from tldts (no Public Suffix List in the SDK) ---

    #[test]
    #[ignore = "requires a Public Suffix List; tldts returns example.co.uk"]
    fn psl_multi_label_suffix() {
        let dir = vec![entry("example.co.uk", "", true, false)];
        assert!(find_match(&candidate(1, &["https://login.example.co.uk"]), &dir).is_some());
    }

    #[test]
    #[ignore = "requires a Public Suffix List; tldts (allowPrivateDomains) returns user.github.io"]
    fn psl_private_suffix() {
        let dir = vec![entry("github.io", "", true, false)];
        assert!(find_match(&candidate(1, &["https://user.github.io"]), &dir).is_none());
    }

    #[test]
    fn registrable_domain_single_label_suffix() {
        assert_eq!(
            registrable_domain("a.b.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("intranet"), None);
    }

    // --- evaluateCipher / buildPasskeyCipherRow ---

    #[test]
    fn evaluate_returns_row_for_matching_cipher() {
        let dir = directory();
        let row = PasskeyDirectory::new(&dir)
            .evaluate(&candidate(1, &["https://example.com"]))
            .unwrap();
        assert_eq!(
            row,
            PasskeyOpportunity {
                id: id(1),
                supports_passkey_login: true,
                supports_passkey_mfa: false,
                instructions: Some("https://example.com/setup".to_owned()),
            }
        );
    }

    #[test]
    fn evaluate_returns_none_for_non_matching_cipher() {
        let dir = directory();
        assert!(
            PasskeyDirectory::new(&dir)
                .evaluate(&candidate(1, &["https://nomatch.com"]))
                .is_none()
        );
    }

    #[test]
    fn empty_instructions_become_none() {
        let dir = directory();
        let row = PasskeyDirectory::new(&dir)
            .evaluate(&candidate(1, &["https://test.com"]))
            .unwrap();
        assert_eq!(row.instructions, None);
        assert!(row.supports_passkey_mfa);
        assert!(!row.supports_passkey_login);
    }

    #[test]
    fn missing_instructions_stay_none() {
        let dir = vec![PasskeyDirectoryEntry {
            domain_name: Some("example.com".to_owned()),
            ..Default::default()
        }];
        let row = PasskeyDirectory::new(&dir)
            .evaluate(&candidate(1, &["https://example.com"]))
            .unwrap();
        assert_eq!(row.instructions, None);
    }

    #[test]
    fn candidate_deserializes_camel_case() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "type": 1,
            "uris": ["https://example.com"],
            "hasFido2Credentials": false,
            "isDeleted": false,
            "viewPassword": true
        }"#;
        let c: PasskeyCandidate = serde_json::from_str(json).unwrap();
        assert_eq!(c, candidate(1, &["https://example.com"]));
    }
}
