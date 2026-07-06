//! Secret and configuration value resolution from various sources.
//!
//! The [`CredentialResolver`] trait abstracts the mechanism by which per-target
//! credentials (e.g. service-principal secrets, script paths) are obtained.  The
//! default implementation reads from environment variables; future implementations
//! can read from config files or the Bitwarden Secrets Manager.
//!
//! # Resolver contract
//!
//! A resolved credential map's keys are the **suffix** portion of the
//! environment variable name — i.e. everything after the `<TARGET_ID>_` prefix.
//! For example, for target id `abc-123`, the variable `ABC_123_CLIENT_SECRET`
//! resolves under the key `CLIENT_SECRET`.
//!
//! Variable **values** are wrapped in [`zeroize::Zeroizing`] via
//! [`bitwarden_sensitive_value::Sensitive`] so that they are wiped from memory
//! when dropped.  Variable **names** are safe to log/report; values never are.

pub(crate) mod env;

use std::collections::HashMap;

use async_trait::async_trait;
use bitwarden_sensitive_value::Sensitive;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::models::TargetKind;

// ---------------------------------------------------------------------------
// ResolvedCredentials
// ---------------------------------------------------------------------------

/// A map of resolved credential values keyed by their **suffix** (the portion
/// of the environment variable name after the `<TARGET_ID>_` prefix).
///
/// Values are [`Sensitive<Zeroizing<String>>`] so that the raw secret bytes
/// are zeroed when dropped.
///
/// # Example
///
/// For a variable `ABC_123_CLIENT_SECRET`, the entry is stored under the key
/// `"CLIENT_SECRET"`.  Retrieving it:
///
/// ```ignore
/// use bitwarden_sensitive_value::ExposeSensitive as _;
/// let val = creds.get("CLIENT_SECRET").map(|s| s.expose());
/// ```
#[derive(Debug)]
pub(crate) struct ResolvedCredentials {
    inner: HashMap<String, Sensitive<Zeroizing<String>>>,
}

impl ResolvedCredentials {
    /// Creates a new, empty credential map.
    pub(crate) fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Inserts a credential.  `key` is the suffix (e.g. `"CLIENT_SECRET"`);
    /// `value` is the raw secret string.
    pub(crate) fn insert(&mut self, key: String, value: String) {
        self.inner
            .insert(key, Sensitive::from(Zeroizing::new(value)));
    }

    /// Returns a reference to the value for the given suffix key, or `None`.
    pub(crate) fn get(&self, key: &str) -> Option<&Sensitive<Zeroizing<String>>> {
        self.inner.get(key)
    }

    /// Returns an iterator over all `(key, value)` pairs.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Sensitive<Zeroizing<String>>)> {
        self.inner.iter()
    }
}

impl Default for ResolvedCredentials {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ResolveError
// ---------------------------------------------------------------------------

/// Errors that can occur when resolving credentials for a target system.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// One or more required environment variables are absent.
    ///
    /// The payload carries the **variable names** only — never values — so it
    /// is safe to include in failure reports.
    #[error("missing required credential variables: {}", .0.join(", "))]
    Missing(Vec<String>),
}

// ---------------------------------------------------------------------------
// CredentialResolver trait
// ---------------------------------------------------------------------------

/// Resolves credentials for a given target system.
///
/// Implementations are expected to be cheap to clone/share (`Arc<dyn
/// CredentialResolver>`).  Resolution is `async` so that future implementations
/// can talk to an external secrets manager.
#[async_trait]
pub(crate) trait CredentialResolver: Send + Sync {
    /// Resolves all credentials for the given target.
    ///
    /// On success returns a [`ResolvedCredentials`] map containing at least the
    /// required suffixes for `kind`.  On failure returns a [`ResolveError`]
    /// whose payload contains only safe-to-log variable names.
    async fn resolve(
        &self,
        target_system_id: Uuid,
        kind: TargetKind,
    ) -> Result<ResolvedCredentials, ResolveError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_credentials_get_and_insert() {
        let mut creds = ResolvedCredentials::new();
        assert!(creds.get("FOO").is_none());
        creds.insert("FOO".to_string(), "bar".to_string());
        assert!(creds.get("FOO").is_some());
    }

    #[test]
    fn resolve_error_missing_contains_names() {
        let names = vec!["TENANT_ID".to_string(), "CLIENT_SECRET".to_string()];
        let err = ResolveError::Missing(names.clone());
        let msg = err.to_string();
        assert!(msg.contains("TENANT_ID"));
        assert!(msg.contains("CLIENT_SECRET"));
    }
}
