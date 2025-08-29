use std::collections::{hash_map::Entry, HashMap, HashSet};

use url::Url;

use crate::Cipher;

/// A grouping of ciphers considered duplicates under a specific display key.
#[derive(Debug)]
pub struct DuplicateSet<'a> {
    /// Human-readable grouping key (e.g. "username+uri: alice @ example.com").
    pub key: String,
    /// All ciphers participating in this duplicate group.
    pub ciphers: Vec<&'a Cipher>,
}

/// Strategy for determining whether two login URIs should be considered the same
/// when detecting duplicate ciphers.
///
/// The strategies progressively narrow what is considered a match:
/// * Domain: compares only the registrable domain (e.g. `sub.example.co.uk` -> `example.co.uk`).
/// * Hostname: compares the full hostname without port (e.g. `sub.example.com`).
/// * Host: compares hostname plus a port (if present)
/// * Exact: compares the full original URI string verbatim.
pub enum DuplicateUriMatchType {
    /// Match by the effective registrable domain portion of the host.
    Domain,
    /// Match by the full hostname (subdomains preserved), excluding any port.
    Hostname,
    /// Match by hostname plus a port (if present).
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
    // currently only removes internal and external whitespace and lowercases
    let normalized = name
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    normalized
}

/// Normalize a URI according to the chosen duplicate matching strategy.
///
/// Returns an `Option<String>` where:
/// * Domain uses the public suffix list (psl) to collapse `a.b.example.co.uk` -> `example.co.uk`.
/// * Hostname preserves the full hostname exactly as parsed (no port).
/// * Host appends port (if present) to the hostname.
/// * Exact performs no normalization
///
/// Examples:
/// ```text
/// Strategy=Domain:   https://app.eu.example.com/login  => Some("example.com")
/// Strategy=Hostname: https://app.eu.example.com/login  => Some("app.eu.example.com")
/// Strategy=Host:     https://app.eu.example.com/login  => Some("app.eu.example.com:443")
/// Strategy=Host:     http://example.com:80             => Some("example.com:80")
/// Strategy=Exact:    not a uri                         => Some("not a uri")
/// Strategy=Domain:   not a uri                         => None (parse fails)
/// ```
fn normalize_uri_for_matching(uri: &str, strategy: &DuplicateUriMatchType) -> Option<String> {
    match strategy {
        DuplicateUriMatchType::Domain => Url::parse(uri).ok().and_then(|url| {
            url.host_str()
                .and_then(|hostname| psl::domain_str(hostname).map(|domain| domain.to_string()))
        }),
        DuplicateUriMatchType::Hostname => Url::parse(uri)
            .ok()
            .and_then(|url| url.host_str().map(|hostname| hostname.to_string())),
        DuplicateUriMatchType::Host => Url::parse(uri).ok().map(|url| {
            let hostname = url.host_str().map(|hostname| hostname.to_string());
            format!(
                "{}:{}",
                hostname.unwrap_or_default(),
                url.port().unwrap_or_default()
            )
        }),
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
/// highest‑precedence bucket is retained (username+uri > username+name > name-only).
///
/// Display key formats:
/// * username+uri: <user> @ <uri_part>
/// * username+name: <user> & <Name>
/// * username+name: & <Name> (blank username for name-only)
///
/// A cipher can appear in multiple returned sets if it legitimately matches
/// distinct groups (e.g., the same username across two distinct URIs).
pub fn find_duplicate_sets<'a>(
    ciphers: &'a [Cipher],
    strategy: DuplicateUriMatchType,
) -> Vec<DuplicateSet<'a>> {
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

    // (BucketKind, grouping_key) -> Vec<&Cipher>
    let mut buckets: HashMap<(BucketKind, String), Vec<&'a Cipher>> = HashMap::new();

    for cipher in ciphers.iter() {
        // Extract username (if login) and list of URIs
        let (username, uri_strings): (String, Vec<String>) = if let Some(login) = &cipher.login {
            let username = login
                .username
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_default()
                .trim()
                .to_string();
            let uris = login
                .uris
                .as_ref()
                .map(|all_uris| {
                    all_uris
                        .iter()
                        .filter_map(|curr_uri| curr_uri.uri.as_ref().map(|e| e.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            (username, uris)
        } else {
            (String::new(), Vec::new())
        };
        let has_username = !username.is_empty();

        // Username + URI buckets (dedupe normalized URIs per cipher)
        if has_username && !uri_strings.is_empty() {
            let mut per_cipher_seen: HashSet<String> = HashSet::new();
            for raw_uri in uri_strings.iter() {
                if let Some(norm_uri) = normalize_uri_for_matching(raw_uri, &strategy) {
                    if per_cipher_seen.insert(norm_uri.clone()) {
                        buckets
                            .entry((BucketKind::UsernameUri, format!("{username}||{norm_uri}")))
                            .or_default()
                            .push(cipher);
                    }
                }
            }
        }

        // Name-based buckets
        let raw_name = cipher.name.to_string();
        let trimmed_name = raw_name.trim();
        if !trimmed_name.is_empty() {
            let norm_name = normalize_name_for_matching(trimmed_name);
            if !norm_name.is_empty() {
                // guard in case normalization strips everything
                if has_username {
                    buckets
                        .entry((BucketKind::UsernameName, format!("{username}||{norm_name}")))
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
    // Prefer stable cipher IDs; fall back to pointer addresses (prefixed) only if an ID is absent.
    fn signature(ciphers: &[&Cipher]) -> String {
        let mut ids: Vec<String> = ciphers
            .iter()
            .map(|c| {
                if let Some(id) = c.id.as_ref() {
                    id.to_string()
                } else {
                    // Defensive fallback uses a pointer to cipher memory address (avoids unwrap /
                    // expect) Prefix with _ptr to avoid accidental collision
                    // with a real UUID string.
                    format!("_ptr{:016x}", *c as *const Cipher as usize)
                }
            })
            .collect();
        ids.sort_unstable();
        ids.join("|")
    }

    // signature -> (precedence, BucketKind, grouping_key, members)
    let mut strongest_matches: HashMap<String, (u8, BucketKind, String, Vec<&Cipher>)> =
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

    // Convert to DuplicateSet with Web Vault display key formatting
    let mut sets: Vec<DuplicateSet> = strongest_matches
        .into_values()
        .map(|(_p, kind, key, members)| {
            let display = match kind {
                BucketKind::UsernameUri => {
                    if let Some((user, uri_part)) = key.split_once("||") {
                        format!("username+uri: {user} @ {uri_part}")
                    } else {
                        format!("username+uri: {key}")
                    }
                }
                BucketKind::UsernameName => {
                    if let Some((user, _canon)) = key.split_once("||") {
                        let display_name = members
                            .first()
                            .map(|c| c.name.to_string())
                            .unwrap_or_default();
                        let trimmed = display_name.trim();
                        format!("username+name: {user} & {trimmed}")
                    } else {
                        let display_name = members
                            .first()
                            .map(|c| c.name.to_string())
                            .unwrap_or_default();
                        let trimmed = display_name.trim();
                        format!("username+name:  & {trimmed}")
                    }
                }
                BucketKind::NameOnly => {
                    let display_name = members
                        .first()
                        .map(|c| c.name.to_string())
                        .unwrap_or_default();
                    let trimmed = display_name.trim();
                    format!("username+name:  & {trimmed}")
                }
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
    use std::str::FromStr;

    use bitwarden_crypto::EncString;
    use chrono::Utc;

    use super::*;
    use crate::{
        cipher::{
            cipher::{CipherRepromptType, CipherType},
            login::{Login, LoginUri},
        },
        Cipher,
    }; // needed for EncString::from_str

    // Helper to build a login cipher
    fn make_login_cipher(
        id: Option<&str>,
        username: Option<&str>,
        uris: &[&str],
        name: &str,
    ) -> Cipher {
        Cipher {
            id: id.map(|s| s.parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: EncString::from_str(name).unwrap(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(Login {
                username: username.map(|u| EncString::from_str(u).unwrap()),
                password: None,
                password_revision_date: None,
                uris: if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|u| LoginUri {
                                uri: Some(EncString::from_str(u).unwrap()),
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

    // Helper to build non-login cipher (SecureNote)
    fn make_note_cipher(id: Option<&str>, name: &str) -> Cipher {
        Cipher {
            id: id.map(|s| s.parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: EncString::from_str(name).unwrap(),
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

    // ---- normalize_name_for_matching tests ----
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

    // ---- normalize_uri_for_matching tests ----

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
    fn test_normalize_uri_hostname_and_host() {
        let uri = "https://app.example.com:8443/a";
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Hostname),
            Some("app.example.com".to_string())
        );
        // Host strategy uses explicit port only, defaulting to 0 if absent (per current
        // implementation)
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("app.example.com:8443".to_string())
        );
    }

    #[test]
    fn test_normalize_uri_host_no_explicit_port_results_zero() {
        let uri = "https://example.com/path"; // no explicit port -> :0 by implementation
        assert_eq!(
            normalize_uri_for_matching(uri, &DuplicateUriMatchType::Host),
            Some("example.com:0".to_string())
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

    // ---- find_duplicate_sets tests ----

    #[test]
    fn test_find_duplicate_sets_empty_input() {
        let sets = find_duplicate_sets(&[], DuplicateUriMatchType::Domain);
        assert!(sets.is_empty());
    }

    #[test]
    fn test_username_uri_duplicate_basic() {
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
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 1); // domain example.com
        assert!(sets[0].key.starts_with("username+uri:"));
        assert_eq!(sets[0].ciphers.len(), 2);
    }

    #[test]
    fn test_username_name_precedence_lower_than_uri() {
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
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 1);
        assert!(sets[0].key.starts_with("username+uri:"));
    }

    #[test]
    fn test_name_only_duplicates() {
        let n1 = make_note_cipher(Some("33333333-3333-3333-3333-333333333333"), "Shared Note");
        let n2 = make_note_cipher(
            Some("44444444-4444-4444-4444-444444444444"),
            "  shared  note  ",
        );
        let ciphers = vec![n1, n2];
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 1);
        assert!(sets[0].key.contains("Shared Note") || sets[0].key.contains("shared  note"));
    }

    #[test]
    fn test_cipher_in_multiple_sets_via_distinct_uris() {
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
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 2);
        let multi_appearances = sets
            .iter()
            .filter(|s| s.ciphers.iter().any(|c| c.name.to_string() == "Multi"));
        assert_eq!(multi_appearances.count(), 2);
    }

    #[test]
    fn test_identical_membership_multiple_normalized_uris_collapse() {
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
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Hostname);
        assert_eq!(sets.len(), 1);
        assert!(
            sets[0].key.contains("user @ x.example.com")
                || sets[0].key.contains("user @ y.example.com")
        );
    }

    #[test]
    fn test_per_cipher_uri_deduplication() {
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
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Hostname);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].ciphers.len(), 2);
    }

    #[test]
    fn test_domain_strategy_groups_subdomains() {
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
    }

    #[test]
    fn test_missing_ids_still_group_using_pointer_fallback() {
        let c1 = make_note_cipher(None, "SameName");
        let c2 = make_note_cipher(None, "  same name  ");
        let ciphers = vec![c1, c2];
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 1);
        assert!(sets[0].key.contains("SameName") || sets[0].key.contains("same name"));
    }

    #[test]
    fn test_username_name_does_not_cross_with_name_only() {
        let login = make_login_cipher(
            Some("14141414-1414-1414-1414-141414141414"),
            Some("user"),
            &[],
            "Duplicate",
        );
        let note1 = make_note_cipher(Some("15151515-1515-1515-1515-151515151515"), "Duplicate");
        let note2 = make_note_cipher(Some("16161616-1616-1616-1616-161616161616"), "duplicate");
        let ciphers = vec![login, note1, note2];
        let sets = find_duplicate_sets(&ciphers, DuplicateUriMatchType::Domain);
        assert_eq!(sets.len(), 1);
        assert!(sets[0].key.starts_with("username+name:  &"));
        assert_eq!(sets[0].ciphers.len(), 2);
    }
}
