//! Per-target credential resolution. [`config::ConfigCredentialResolver`] is the active resolver:
//! the config file wins per key, and the environment is the fallback.

pub(crate) mod config;
pub(crate) mod env;

use std::collections::HashMap;

use async_trait::async_trait;
use bitwarden_sensitive_value::Sensitive;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::models::TargetKind;

/// Resolved credentials keyed by suffix, the env var name after the `<TARGET_ID>_` prefix (e.g.
/// `CLIENT_SECRET`). Values are [`Sensitive<Zeroizing<String>>`], zeroed on drop.
#[derive(Debug)]
pub(crate) struct ResolvedCredentials {
    inner: HashMap<String, Sensitive<Zeroizing<String>>>,
}

impl ResolvedCredentials {
    pub(crate) fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, key: String, value: String) {
        self.inner
            .insert(key, Sensitive::from(Zeroizing::new(value)));
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Sensitive<Zeroizing<String>>> {
        self.inner.get(key)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Sensitive<Zeroizing<String>>)> {
        self.inner.iter()
    }
}

impl Default for ResolvedCredentials {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from resolving credentials for a target system.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// Required credentials are missing. Carries their env var names only, never values, so it
    /// is safe to report.
    #[error("missing required credential variables: {}", .0.join(", "))]
    Missing(Vec<String>),
}

/// Resolves credentials for a target system. `async` so an implementation can call an external
/// secrets manager.
#[async_trait]
pub(crate) trait CredentialResolver: Send + Sync {
    /// The resolved map contains at least the suffixes `kind` requires.
    async fn resolve(
        &self,
        target_system_id: Uuid,
        kind: TargetKind,
    ) -> Result<ResolvedCredentials, ResolveError>;
}

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
