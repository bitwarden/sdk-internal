//! # Duplicate cipher detection
//!
//! Duplicate detection utilities for grouping related [`CipherView`] values that
//! appear to represent the same real-world login. Buckets are built along three
//! axes (username+URI, username+name, and name-only) using normalization rules
//! so that visually similar entries (e.g., differing only by whitespace or
//! subdomain) coalesce. When multiple bucket types cover the exact same set of
//! ciphers, only the highest-precedence bucket (username+uri > username+name >
//! name-only) is kept to avoid redundant duplicate reports. A cipher can still
//! appear in multiple returned groups if the underlying membership differs
//! (e.g., the same username across two different domains). Normalization is biased
//! toward collapsing obviously equivalent values without losing distinct data.
//!
//! The logic in this module was originally implemented in the web app
//! [ https://github.com/bitwarden/clients/pull/15967 ]
//! and adapted to the Rust API. Some notable divergences:
//! * The Domain [ DuplicateUriMatchType ] does not support IPv4 and IPv6 addresses in this module
//!   but does so in the Web app
//! * The Host [ DuplicateUriMatchType ] does not support port numbers when they match the default
//!   for a given scheme (80 for http, 443 for https). Only port numbers not matching a scheme's
//!   default will be parsed and retained. This is due to limitations in the url crate and could
//!   likely be fixed using regular expressions.
//!
//! ## Logical flow:
//! 1. Iterate over CipherViews, skipping those without an id (cannot be deleted after review).
//! 2. Derive normalized `login.username`, `login.uris` (strategy dependent) and `cipher.name`.
//! 3. Insert into typed buckets keyed by a canonical composite key.
//! 4. Filter out singleton buckets; collapse identical membership by precedence.
//! 5. Produce stable, human-readable display keys for UI consumption via [`find_duplicate_sets`].

use std::collections::{hash_map::Entry, HashMap, HashSet};

use url::Url;

use crate::cipher::cipher::CipherView;

/// A grouping of ciphers considered duplicates under a specific display key
/// that can be derived from login.username, login.uris, and cipher.name
#[derive(Debug)]
pub struct DuplicateSet<'a> {
    /// Human-readable key (e.g. "username+uri: alice @ example.com").
    pub key: String,
    /// All ciphers participating in the duplicate group.
    pub ciphers: Vec<&'a CipherView>,
}

/// Strategy for determining whether two login URIs should be considered duplicates
///
/// The strategies progressively narrow what is considered a match:
/// * Domain: compares only the registrable domain (e.g. `sub.example.co.uk` -> `example.co.uk`).
/// * Hostname: compares the full hostname without port (e.g. `sub.example.co.uk`).
/// * Host: compares hostname and an explicitly specified port (omits default/implicit ports)
/// * Exact: compares the full original URI string verbatim.
#[derive(Debug, Clone, Copy)]
pub enum DuplicateUriMatchType {
    /// Match by the effective registrable domain portion of the host.
    Domain,
    /// Match by the full hostname (subdomains preserved), excluding any port.
    Hostname,
    /// Match by hostname plus a port (omits default/implicit ports)
    Host,
    /// Match by the exact original URI string with no normalization applied.
    Exact,
}

/// Normalize a cipher name for duplicate comparison:
///
/// 1. Removes *all* Unicode whitespace characters (spaces, tabs, newlines, etc.)
/// 2. Converts the remaining characters to lowercase
///
/// Returns a newly allocated `String` containing the normalized form.
fn normalize_name_for_matching(name: &str) -> String {
    // Allocate once; skip whitespace and push lowercase chars.
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if !ch.is_whitespace() {
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
        }
    }
    out
}

/// Normalize a URI according to the chosen duplicate matching strategy.
///
/// Returns an `Option<String>` where:
/// * Domain uses the public suffix list (psl) to collapse `a.b.example.co.uk` -> `example.co.uk`.
/// * Hostname preserves the full hostname exactly as parsed (no port).
/// * Host appends the explicit port only when one is specified in the URI (see limitations)
/// * Exact performs no normalization
///
/// # Limitations:
/// Unlike the URL parsing library used in the web app
/// https://nodejs.org/api/url.html#the-whatwg-url-api
/// the url crate will strip explicit port numbers
/// matching the default port for a given url scheme:
/// * http://some.domain:80 => some.domain (http default port 80 is not retained)
/// * https://some.domain:443 => some.domain (https default port 443 is not retained)
/// * https://some.domain:4444 => some.domain:4444
///
/// This applies to the Host strategy only.
///
/// Raw IP addresses (IPv4 and IPv6) will not be considered when the Domain strategy is used.
///
/// Examples:
/// ```text
/// Strategy=Domain:   https://app.eu.example.com/login  => Some("example.com")
/// Strategy=Hostname: https://app.eu.example.com/login  => Some("app.eu.example.com")
/// Strategy=Host:     https://app.eu.example.com/login  => Some("app.eu.example.com") (no port provided)
/// Strategy=Host:     https://app.eu.example.com:443/   => Some("example.com") (default port for scheme is lost)
/// Strategy=Host:     https://app.eu.example.com:4444/  => Some("example.com:4444")
/// Strategy=Exact:    not a uri                         => Some("not a uri")
/// Strategy=Domain:   not a uri                         => None (parse fails)
/// ```
fn normalize_uri_for_matching(uri: &str, strategy: &DuplicateUriMatchType) -> Option<String> {
    match strategy {
        DuplicateUriMatchType::Domain => {
            let url = Url::parse(uri).ok()?;
            let host = url.host_str()?;
            // Treat raw IP addresses (v4 or v6) as non-domain (no registrable domain to compare)
            // This is another divergence from the original web app implementation
            if host.parse::<std::net::IpAddr>().is_ok() {
                return None;
            }
            let host_lower = host.to_ascii_lowercase();
            psl::domain_str(&host_lower).map(str::to_string)
        }
        DuplicateUriMatchType::Hostname => {
            let url = Url::parse(uri).ok()?;
            let host = url.host_str()?;
            Some(host.to_string())
        }
        DuplicateUriMatchType::Host => {
            let url = Url::parse(uri).ok()?;
            let host = url.host_str()?;
            if let Some(port) = url.port() {
                Some(format!("{host}:{port}"))
            } else {
                Some(host.to_string())
            }
        }
        DuplicateUriMatchType::Exact => Some(uri.to_string()),
    }
}
/// Build groups of duplicated ciphers
///
/// Buckets (size >= 2 kept):
/// * username+uri: username and each normalized URI (strategy-specific)
/// * username+name: username and normalized name
/// * name-only: normalized name when the username is missing
///
/// Normalization:
/// * URIs: [normalize_uri_for_matching] and the provided strategy
/// * Names: [normalize_name_for_matching] (whitespace removed, lowercase)
///
/// When different buckets contain the exact same cipher membership, only the
/// highest-precedence bucket is retained (username+uri > username+name > name-only).
///
/// Display key formats:
/// * username+uri: <user> @ <uri_part>
/// * username+name: <user> & <Name>
/// * name-only: & <Name> (blank username)
///
/// A cipher can appear in multiple returned sets if it legitimately matches
/// distinct groups (e.g., the same username across two distinct URIs).
pub fn find_duplicate_sets<'a>(
    ciphers: &'a [CipherView],
    strategy: DuplicateUriMatchType,
) -> Vec<DuplicateSet<'a>> {
    const KEY_SEP: &str = "||"; // separator between composite key parts
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
    enum BucketKind {
        UsernameUri,
        UsernameName,
        NameOnly,
    }

    impl BucketKind {
        fn precedence(self) -> u8 {
            match self {
                BucketKind::UsernameUri => 3,
                BucketKind::UsernameName => 2,
                BucketKind::NameOnly => 1,
            }
        }
    }

    let mut buckets: HashMap<(BucketKind, String), Vec<&'a CipherView>> = HashMap::new();

    for cipher in ciphers.iter() {
        if cipher.id.is_none() {
            continue;
        }

        // Extract username (if login) and list of URIs
        let (username, uri_strings): (String, Vec<String>) = if let Some(login) = &cipher.login {
            let username = login
                .username
                .as_ref()
                .map(|u| u.trim().to_string())
                .unwrap_or_default();
            let uris = login
                .uris
                .as_ref()
                .map(|all_uris| {
                    all_uris
                        .iter()
                        .filter_map(|curr_uri| curr_uri.uri.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            (username, uris)
        } else {
            (String::new(), Vec::new())
        };
        let has_username = !username.is_empty();

        // Username + URI buckets (avoid redundant URIs for each cipher)
        if has_username && !uri_strings.is_empty() {
            let mut per_cipher_seen: HashSet<String> = HashSet::new();
            for raw_uri in uri_strings.iter() {
                if let Some(norm_uri) = normalize_uri_for_matching(raw_uri, &strategy) {
                    if per_cipher_seen.insert(norm_uri.clone()) {
                        buckets
                            .entry((
                                BucketKind::UsernameUri,
                                format!("{username}{KEY_SEP}{norm_uri}"),
                            ))
                            .or_default()
                            .push(cipher);
                    }
                }
            }
        }

        // Name-based buckets
        let raw_name = cipher.name.clone();
        let trimmed_name = raw_name.trim();
        if !trimmed_name.is_empty() {
            let norm_name = normalize_name_for_matching(trimmed_name);
            if !norm_name.is_empty() {
                // guard in case normalization strips everything
                if has_username {
                    buckets
                        .entry((
                            BucketKind::UsernameName,
                            format!("{username}{KEY_SEP}{norm_name}"),
                        ))
                        .or_default()
                        .push(cipher);
                } else {
                    buckets
                        .entry((BucketKind::NameOnly, norm_name))
                        .or_default()
                        .push(cipher);
                }
            }
        }
    }

    // Helper to produce a stable, order-independent membership signature.
    // All ciphers inserted into buckets have an id (guard enforced earlier).
    fn signature(ciphers: &[&CipherView]) -> String {
        let mut ids: Vec<String> = Vec::with_capacity(ciphers.len());
        for c in ciphers.iter() {
            if let Some(id) = &c.id {
                ids.push(id.to_string());
            }
        }
        ids.sort_unstable();
        ids.join("|")
    }

    // key: signature -> value: (precedence, BucketKind, grouping_key, members)
    let mut strongest_matches: HashMap<String, (u8, BucketKind, String, Vec<&CipherView>)> =
        HashMap::new();

    for ((kind, key), members) in buckets.into_iter() {
        if members.len() < 2 {
            continue;
        }
        let signature = signature(&members);
        let precedence = kind.precedence();
        match strongest_matches.entry(signature) {
            Entry::Vacant(vacant) => {
                vacant.insert((precedence, kind, key, members));
            }
            Entry::Occupied(mut occupied) => {
                if precedence > occupied.get().0 {
                    occupied.insert((precedence, kind, key, members));
                }
            }
        }
    }

    // Convert to DuplicateSet with Web app display key formatting
    let mut sets: Vec<DuplicateSet> = strongest_matches
        .into_values()
        .map(|(_p, kind, key, members)| {
            let first_name_trimmed = members
                .first()
                .map(|c| c.name.trim().to_string())
                .unwrap_or_default();
            let display = match kind {
                BucketKind::UsernameUri => key
                    .split_once(KEY_SEP)
                    .map(|(user, uri_part)| format!("username+uri: {user} @ {uri_part}"))
                    .unwrap_or_else(|| format!("username+uri: {key}")),
                BucketKind::UsernameName => key
                    .split_once(KEY_SEP)
                    .map(|(user, _)| format!("username+name: {user} & {first_name_trimmed}"))
                    .unwrap_or_else(|| format!("username+name:  & {first_name_trimmed}")),
                BucketKind::NameOnly => format!("username+name:  & {first_name_trimmed}"),
            };
            DuplicateSet {
                key: display,
                ciphers: members,
            }
        })
        .collect();

    sets.sort_by(|a, b| a.key.cmp(&b.key));
    sets
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::cipher::{
        cipher::{CipherRepromptType, CipherType, CipherView},
        login::{LoginUriView, LoginView},
    };

    // helper to construct a CipherView for testing
    fn make_login_cipher(
        id: Option<&str>,
        username: Option<&str>,
        uris: &[&str],
        name: &str,
    ) -> CipherView {
        CipherView {
            id: id.map(|s| s.parse().expect("valid UUID literal")),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: name.to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: username.map(|u| u.to_string()),
                password: None,
                password_revision_date: None,
                uris: if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|u| LoginUriView {
                                uri: Some(u.to_string()),
                                r#match: None,
                                uri_checksum: None,
                            })
                            .collect(),
                    )
                },
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: false,
            permissions: None,
            view_password: false,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: Utc::now(),
            deleted_date: None,
            revision_date: Utc::now(),
        }
    }

    // Helper to build non-login cipher view (SecureNote)
    fn make_note_cipher(id: Option<&str>, name: &str) -> CipherView {
        CipherView {
            id: id.map(|s| s.parse().expect("valid UUID literal")),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: name.to_string(),
            notes: None,
            r#type: CipherType::SecureNote,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: false,
            permissions: None,
            view_password: false,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: Utc::now(),
            deleted_date: None,
            revision_date: Utc::now(),
        }
    }

    #[test]
    fn test_normalize_name_empty_and_whitespace() {
        assert_eq!(normalize_name_for_matching(""), "");
        assert_eq!(normalize_name_for_matching("   \t \n"), "");
    }

    #[test]
    fn test_normalize_name_internal_whitespace_and_case() {
        assert_eq!(normalize_name_for_matching("My Site"), "mysite");
        assert_eq!(
            normalize_name_for_matching("  Mixed  Case  Name  "),
            "mixedcasename"
        );
        assert_eq!(normalize_name_for_matching("T A B S"), "tabs");
        assert_eq!(
            normalize_name_for_matching("Multi\nLine\tName"),
            "multilinename"
        );
    }

    #[test]
    fn test_normalize_name_unicode_whitespace() {
        // Includes non-breaking space (\u{00A0}) and thin space (\u{2009})
        let s = "Name\u{00A0}\u{2009}With\u{00A0}Spaces";
        assert_eq!(normalize_name_for_matching(s), "namewithspaces");
    }

    #[test]
    fn test_normalize_uri_domain_basic() {
        let uri = "https://sub.example.co.uk/path";
        // Using PSL should reduce to example.co.uk
        let norm = normalize_uri_for_matching(uri, &DuplicateUriMatchType::Domain);
        assert_eq!(norm, Some("example.co.uk".to_string()));
    }

    #[test]
    fn test_normalize_uri_domain_ip_returns_none() {
        let uri = "https://192.168.1.10/login";
        // IP address has no registrable domain
        let norm = normalize_uri_for_matching(uri, &DuplicateUriMatchType::Domain);
        assert_eq!(norm, None);
    }

    #[test]
    fn test_normalize_uri_hostname() {
        let uri = "https://app.example.com:8443/a";
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Hostname),
            Some("app.example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host() {
        let uri = "https://app.example.com:8443/a";
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("app.example.com:8443".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_no_explicit_port() {
        let uri = "https://example.com/path"; // no explicit port -> hostname only
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com".to_string())
        );
    }

    /*
    * Due to limitations in the url crate, port cannot be obtained when it matches
    * the default ports for provided schemes. This is a divergence from the URL
    * parsing library used in the web app: https://nodejs.org/api/url.html#the-whatwg-url-api
    * but should be considered an edge case (most users would not supply scheme and default port
    * and default port shouldn't be included by browser for http & https schemes)
    #[test]
    fn test_normalize_uri_host_explicit_default_port() {
        let uri = "https://example.com:443/path"; // explicit default port retained
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com:443".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_explicit_http_default_port() {
        let uri = "http://example.com:80/path"; // explicit default http port retained
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com:80".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_ipv6_explicit_default_port() {
        let uri = "https://[2001:db8::1]:443/"; // explicit default https port on IPv6
        assert_eq!(normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("[2001:db8::1]:443".to_string())
        );
    }
    */

    #[test]
    fn test_normalize_uri_host_userinfo_no_port() {
        let uri = "https://user:pass@example.com/path"; // userinfo present, no explicit port
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_ipv6_non_default_port() {
        let uri = "https://[2001:db8::1]:8443/"; // IPv6 with non-default port
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("[2001:db8::1]:8443".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_userinfo_explicit_non_default_port() {
        let uri = "https://user:pass@example.com:8443/path"; // userinfo with explicit non-default port
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com:8443".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_exact_invalid_still_returns() {
        let raw = "not a uri";
        assert_eq!(
            normalize_uri_for_matching(raw, &DuplicateUriMatchType::Exact),
            Some(raw.to_string())
        );
        assert_eq!(
            normalize_uri_for_matching(raw, &DuplicateUriMatchType::Domain),
            None
        );
    }

    #[test]
    fn test_find_duplicate_sets_empty_input_all_strategies() {
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&[], strategy);
            assert!(sets.is_empty());
        }
    }

    #[test]
    fn test_username_uri_duplicate_all_strategies() {
        let c1 = make_login_cipher(
            Some("11111111-1111-1111-1111-111111111111"),
            Some("alice"),
            &["https://a.example.com"],
            "Site A",
        );
        let c2 = make_login_cipher(
            Some("22222222-2222-2222-2222-222222222222"),
            Some("alice"),
            &["https://a.example.com"],
            "Site B",
        );
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
            assert!(sets[0].key.starts_with("username+uri:"));
            assert_eq!(sets[0].ciphers.len(), 2);
        }
    }

    #[test]
    fn test_username_name_precedence_lower_than_uri_all_strategies() {
        let c1 = make_login_cipher(
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            Some("bob"),
            &["https://foo.com"],
            "Foo",
        );
        let c2 = make_login_cipher(
            Some("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            Some("bob"),
            &["https://foo.com"],
            "Foo",
        );
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
            assert!(sets[0].key.starts_with("username+uri:"));
        }
    }

    #[test]
    fn test_name_only_duplicates_all_strategies() {
        let n1 = make_note_cipher(Some("33333333-3333-3333-3333-333333333333"), "Shared Note");
        let n2 = make_note_cipher(
            Some("44444444-4444-4444-4444-444444444444"),
            "  shared  note  ",
        );
        let ciphers = vec![n1, n2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
            assert!(sets[0].key.starts_with("username+name:"));
        }
    }

    #[test]
    fn test_cipher_in_multiple_sets_via_distinct_uris_all_strategies() {
        let a = make_login_cipher(
            Some("55555555-5555-5555-5555-555555555555"),
            Some("alice"),
            &["https://a.com", "https://b.com"],
            "Multi",
        );
        let b = make_login_cipher(
            Some("66666666-6666-6666-6666-666666666666"),
            Some("alice"),
            &["https://a.com"],
            "One",
        );
        let c = make_login_cipher(
            Some("77777777-7777-7777-7777-777777777777"),
            Some("alice"),
            &["https://b.com"],
            "Two",
        );
        let ciphers = vec![a, b, c];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 2, "strategy {:?}", strategy);
            let multi_appearances = sets.iter().filter(|s| {
                s.ciphers.iter().any(|c| {
                    c.id.map(|id| id.to_string())
                        == Some("55555555-5555-5555-5555-555555555555".into())
                })
            });
            assert_eq!(multi_appearances.count(), 2);
        }
    }

    #[test]
    fn test_identical_membership_multiple_normalized_uris_collapse_all_strategies() {
        let c1 = make_login_cipher(
            Some("88888888-8888-8888-8888-888888888888"),
            Some("user"),
            &["https://x.example.com", "https://y.example.com"],
            "X",
        );
        let c2 = make_login_cipher(
            Some("99999999-9999-9999-9999-999999999999"),
            Some("user"),
            &["https://x.example.com", "https://y.example.com"],
            "Y",
        );
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
        }
    }

    #[test]
    fn test_per_cipher_uri_deduplication_all_strategies() {
        let c1 = make_login_cipher(
            Some("10101010-1010-1010-1010-101010101010"),
            Some("u"),
            &["https://dup.com", "https://dup.com"],
            "A",
        );
        let c2 = make_login_cipher(
            Some("11111110-1111-1111-1111-111111101111"),
            Some("u"),
            &["https://dup.com", "https://dup.com"],
            "B",
        );
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
            assert_eq!(sets[0].ciphers.len(), 2);
        }
    }

    #[test]
    fn test_domain_strategy_collapses_distinct_subdomains() {
        let c1 = make_login_cipher(
            Some("12121212-1212-1212-1212-121212121212"),
            Some("user"),
            &["https://a.service.example.com"],
            "A",
        );
        let c2 = make_login_cipher(
            Some("13131313-1313-1313-1313-131313131313"),
            Some("user"),
            &["https://b.service.example.com"],
            "B",
        );
        let ciphers_domain = vec![c1.clone(), c2.clone()];
        let sets_domain = find_duplicate_sets(&ciphers_domain, DuplicateUriMatchType::Domain);
        assert_eq!(sets_domain.len(), 1);
        let ciphers_hostname = vec![c1, c2];
        let sets_hostname = find_duplicate_sets(&ciphers_hostname, DuplicateUriMatchType::Hostname);
        assert!(sets_hostname.is_empty());
        let sets_host = find_duplicate_sets(&ciphers_hostname, DuplicateUriMatchType::Host);
        assert!(sets_host.is_empty());
        let sets_exact = find_duplicate_sets(&ciphers_hostname, DuplicateUriMatchType::Exact);
        assert!(sets_exact.is_empty());
    }

    #[test]
    fn test_ciphers_without_ids_are_ignored_all_strategies() {
        let c1 = make_note_cipher(None, "SameName");
        let c2 = make_note_cipher(None, "  same name  ");
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert!(sets.is_empty(), "strategy {:?}", strategy);
        }
    }

    #[test]
    fn test_username_name_does_not_cross_with_name_only_all_strategies() {
        let login = make_login_cipher(
            Some("14141414-1414-1414-1414-141414141414"),
            Some("user"),
            &[],
            "Duplicate",
        );
        let note1 = make_note_cipher(Some("15151515-1515-1515-1515-151515151515"), "Duplicate");
        let note2 = make_note_cipher(Some("16161616-1616-1616-1616-161616161616"), "duplicate");
        let ciphers = vec![login, note1, note2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
            assert!(sets[0].key.starts_with("username+name:  &"));
            assert_eq!(sets[0].ciphers.len(), 2);
        }
    }

    #[test]
    fn test_host_strategy_distinguishes_ports() {
        let c1 = make_login_cipher(
            Some("17171717-1717-1717-1717-171717171717"),
            Some("user"),
            &["https://example.com:8443"],
            "A",
        );
        let c2 = make_login_cipher(
            Some("18181818-1818-1818-1818-181818181818"),
            Some("user"),
            &["https://example.com:9443"],
            "B",
        );
        let ciphers = vec![c1.clone(), c2.clone()];
        // Domain & Hostname collapse (ignore differing ports) -> duplicates
        let sets_domain = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets_domain.len(), 1);
        let sets_hostname = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Hostname);
        assert_eq!(sets_hostname.len(), 1);
        // Host distinguishes ports -> no duplicates
        let sets_host = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Host);
        assert!(sets_host.is_empty());
        // Exact includes full string -> different (ports differ) -> no duplicates
        let sets_exact = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Exact);
        assert!(sets_exact.is_empty());
        // Control: identical ports should duplicate under Host
        let c3 = make_login_cipher(
            Some("19191919-1919-1919-1919-191919191919"),
            Some("user"),
            &["https://example.com:8443"],
            "C",
        );
        let ciphers_same_port = vec![c1, c3];
        let sets_host_same_port =
            find_duplicate_sets(&ciphers_same_port, DuplicateUriMatchType::Host);
        assert_eq!(sets_host_same_port.len(), 1);
    }

    #[test]
    fn test_exact_strategy_requires_full_uri_match() {
        let c1 = make_login_cipher(
            Some("20202020-2020-2020-2020-202020202020"),
            Some("user"),
            &["https://example.com"],
            "A",
        );
        let c2 = make_login_cipher(
            Some("21212121-2121-2121-2121-212121212121"),
            Some("user"),
            &["https://example.com/login"],
            "B",
        );
        let ciphers = vec![c1, c2];
        // Domain / Hostname / Host collapse (same host) -> duplicates
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
        }
        // Exact uses full string -> no duplicates
        let sets_exact = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Exact);
        assert!(sets_exact.is_empty());
    }

    #[test]
    fn test_hostname_strategy_groups_identical_full_subdomain_only() {
        // Two identical subdomain hosts should group for all strategies.
        let c1 = make_login_cipher(
            Some("22222222-3333-4444-5555-666666666666"),
            Some("user"),
            &["https://login.app.example.com"],
            "One",
        );
        let c2 = make_login_cipher(
            Some("77777777-8888-9999-aaaa-bbbbbbbbbbbb"),
            Some("user"),
            &["https://login.app.example.com"],
            "Two",
        );
        let ciphers = vec![c1, c2];
        for strategy in [
            DuplicateUriMatchType::Domain,
            DuplicateUriMatchType::Hostname,
            DuplicateUriMatchType::Host,
            DuplicateUriMatchType::Exact,
        ] {
            let sets = find_duplicate_sets(&ciphers, strategy);
            assert_eq!(sets.len(), 1, "strategy {:?}", strategy);
        }
    }

    #[test]
    fn test_hostname_strategy_ipv6_grouping() {
        // IPv6 host should produce duplicates under Hostname/Host/Exact but Domain (IP) ignored.
        let c1 = make_login_cipher(
            Some("abcdabcd-abcd-abcd-abcd-abcdabcdabcd"),
            Some("user"),
            &["https://[2001:db8::1]/login"],
            "One",
        );
        let c2 = make_login_cipher(
            Some("dcba4321-dcba-4321-dcba-4321dcba4321"),
            Some("user"),
            &["https://[2001:db8::1]/account"],
            "Two",
        );
        let ciphers = vec![c1, c2];
        let sets_domain = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert!(sets_domain.is_empty());
        // Hostname groups (same host w/out port)
        let sets_hostname = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Hostname);
        assert_eq!(sets_hostname.len(), 1);
        // Host groups (no port specified)
        let sets_host = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Host);
        assert_eq!(sets_host.len(), 1);
        // Exact considers full strings different (paths differ) so no grouping
        let sets_exact = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Exact);
        assert!(sets_exact.is_empty());
    }
}
