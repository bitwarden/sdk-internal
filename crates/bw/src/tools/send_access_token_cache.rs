//! Persistent cache for Send access tokens, so repeat `bw receive` / `bw send receive` calls for
//! the same Send within a token's validity window don't re-prompt for a password or OTP.
//!
//! Keyed on `(resolved_host, send_id)`, not `send_id` alone. `resolved_host` is whatever
//! `receive::resolve_urls` decided to talk to for this invocation, so a cached token can never
//! be looked up under a host other than the one it was actually minted against. This
//! is deliberate: legacy's own cache (`default-send-token.service.ts`) is keyed on `sendId`
//! alone with no host component, which is part of what PM-40120 tracks — this cache does not
//! replicate that.
//!
//! A malformed, unreadable, or unwritable cache file never fails the caller: the cache is an
//! optimization over minting a fresh token, not something `bw receive` depends on to function.
//!
//! This module has no notion of trust — it will cache anything a caller asks it to. The
//! restriction to trusted hosts only (matching the corresponding TS client fix) is enforced at
//! the call site in `receive::run_receive`, gated on the `trusted` flag `resolve_urls` returns.

use std::{collections::HashMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::platform::appdata_dir;

/// Milliseconds of slack subtracted from a token's real expiry before treating a cached entry as
/// usable, so a cache hit doesn't get used moments before the server would reject it anyway.
/// Mirrors the legacy CLI's 5-second threshold (`SendAccessToken.isExpired`).
const EXPIRY_SLACK_MS: i64 = 5_000;

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    entries: HashMap<String, CachedToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedToken {
    token: String,
    expires_at: i64,
}

fn cache_key(resolved_host: &str, send_id: &str) -> String {
    format!("{resolved_host}|{send_id}")
}

fn cache_path() -> Option<std::path::PathBuf> {
    appdata_dir()
        .ok()
        .map(|dir| dir.join("send_access_tokens.json"))
}

fn read_cache_from(path: &Path) -> CacheFile {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => CacheFile::default(),
    }
}

fn write_cache_to(path: &Path, cache: &CacheFile) {
    let Ok(json) = serde_json::to_vec(cache) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = super::file_output::write_file_private(path, &json);
}

/// Returns a cached, still-valid token for `(resolved_host, send_id)`, if any.
pub(crate) fn get(resolved_host: &str, send_id: &str) -> Option<String> {
    let path = cache_path()?;
    let cache = read_cache_from(&path);
    let entry = cache.entries.get(&cache_key(resolved_host, send_id))?;
    let now = chrono::Utc::now().timestamp_millis();
    (entry.expires_at - EXPIRY_SLACK_MS > now).then(|| entry.token.clone())
}

/// Caches `token` for `(resolved_host, send_id)`, expiring at `expires_at` (epoch-ms, matching
/// [`bitwarden_auth::send_access::SendAccessTokenResponse::expires_at`]).
pub(crate) fn set(resolved_host: &str, send_id: &str, token: &str, expires_at: i64) {
    let Some(path) = cache_path() else {
        return;
    };
    let mut cache = read_cache_from(&path);
    cache.entries.insert(
        cache_key(resolved_host, send_id),
        CachedToken {
            token: token.to_string(),
            expires_at,
        },
    );
    write_cache_to(&path, &cache);
}

/// Evicts a cached entry, e.g. after the server rejects a token the cache believed was still
/// valid (clock skew, or server-side revocation before natural expiry).
pub(crate) fn evict(resolved_host: &str, send_id: &str) {
    let Some(path) = cache_path() else {
        return;
    };
    let mut cache = read_cache_from(&path);
    if cache
        .entries
        .remove(&cache_key(resolved_host, send_id))
        .is_some()
    {
        write_cache_to(&path, &cache);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bw-send-access-token-cache-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    fn cache_file_path() -> PathBuf {
        tempdir().join("send_access_tokens.json")
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    #[test]
    fn get_returns_none_when_file_is_missing() {
        let path = cache_file_path();
        let cache = read_cache_from(&path);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn set_then_get_round_trips_a_token() {
        let path = cache_file_path();
        let mut cache = read_cache_from(&path);
        cache.entries.insert(
            cache_key("https://api.example.com", "send-1"),
            CachedToken {
                token: "tok".to_string(),
                expires_at: now_ms() + 60_000,
            },
        );
        write_cache_to(&path, &cache);

        let reloaded = read_cache_from(&path);
        let entry = reloaded
            .entries
            .get(&cache_key("https://api.example.com", "send-1"))
            .unwrap();
        assert_eq!(entry.token, "tok");
    }

    #[test]
    fn different_hosts_do_not_collide_for_the_same_send_id() {
        let path = cache_file_path();
        let mut cache = read_cache_from(&path);
        cache.entries.insert(
            cache_key("https://real.example.com", "send-1"),
            CachedToken {
                token: "real-token".to_string(),
                expires_at: now_ms() + 60_000,
            },
        );
        write_cache_to(&path, &cache);

        let reloaded = read_cache_from(&path);
        assert!(
            !reloaded
                .entries
                .contains_key(&cache_key("https://attacker.example.com", "send-1")),
            "a token cached under one host must not be visible under a different host, \
             even for the same send id"
        );
    }

    #[test]
    fn expired_entries_are_not_returned() {
        let path = cache_file_path();
        let mut cache = read_cache_from(&path);
        cache.entries.insert(
            cache_key("https://api.example.com", "send-1"),
            CachedToken {
                token: "tok".to_string(),
                expires_at: now_ms() - 1,
            },
        );
        write_cache_to(&path, &cache);

        let reloaded = read_cache_from(&path);
        let entry = reloaded
            .entries
            .get(&cache_key("https://api.example.com", "send-1"))
            .unwrap();
        assert!(entry.expires_at - EXPIRY_SLACK_MS <= now_ms());
    }

    #[test]
    fn a_corrupt_file_is_treated_as_empty_rather_than_an_error() {
        let path = cache_file_path();
        std::fs::write(&path, b"not json").unwrap();
        let cache = read_cache_from(&path);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn evict_removes_only_the_matching_entry() {
        let path = cache_file_path();
        let mut cache = read_cache_from(&path);
        cache.entries.insert(
            cache_key("https://api.example.com", "send-1"),
            CachedToken {
                token: "tok-1".to_string(),
                expires_at: now_ms() + 60_000,
            },
        );
        cache.entries.insert(
            cache_key("https://api.example.com", "send-2"),
            CachedToken {
                token: "tok-2".to_string(),
                expires_at: now_ms() + 60_000,
            },
        );
        write_cache_to(&path, &cache);

        cache
            .entries
            .remove(&cache_key("https://api.example.com", "send-1"));
        write_cache_to(&path, &cache);

        let reloaded = read_cache_from(&path);
        assert!(
            !reloaded
                .entries
                .contains_key(&cache_key("https://api.example.com", "send-1"))
        );
        assert!(
            reloaded
                .entries
                .contains_key(&cache_key("https://api.example.com", "send-2"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_file_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = cache_file_path();
        write_cache_to(&path, &CacheFile::default());

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "send access token cache must be owner-only");
    }
}
