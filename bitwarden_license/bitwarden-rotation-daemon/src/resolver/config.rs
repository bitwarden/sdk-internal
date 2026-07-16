//! Config-file-based credential resolver.
//!
//! [`ConfigCredentialResolver`] layers a per-target TOML configuration on top of
//! [`crate::resolver::env::EnvCredentialResolver`].  Resolution order, per credential key:
//!
//! 1. **Config file** (`[targets.<uuid>]`) — wins unconditionally.
//! 2. **Environment variable** — fallback for any key not set in the config file.
//!
//! The env var name is always used as the actionable hint when a required key is missing,
//! regardless of whether the value was expected from the config file or the environment.
//! This keeps operator-visible error messages consistent and actionable.
//!
//! # Security note
//!
//! `client_secret` is deliberately absent from [`TargetEntry`].  Secrets must be supplied
//! via environment variables only; the config file is typically checked in to a repo and
//! must not hold credentials.

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use super::{CredentialResolver, ResolveError, ResolvedCredentials};
use crate::{
    api::models::TargetKind,
    resolver::env::{prefix_for, required_suffixes},
};

// ---------------------------------------------------------------------------
// TargetEntry
// ---------------------------------------------------------------------------

/// Per-target credential overrides from the `[targets]` TOML section.
///
/// All fields are optional.  Any `Some` value shadows the corresponding environment
/// variable.  The `client_secret` field is intentionally absent — secrets must be
/// supplied via environment variables only.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetEntry {
    /// Path to the custom-script executable (`SCRIPT` suffix).
    pub(crate) script: Option<String>,
    /// Azure AD tenant identifier (`TENANT_ID` suffix).
    pub(crate) tenant_id: Option<String>,
    /// Application (client) ID of the service principal (`CLIENT_ID` suffix).
    pub(crate) client_id: Option<String>,
}

impl TargetEntry {
    /// Return an iterator over `(suffix, value)` pairs for all `Some` fields.
    fn overrides(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("SCRIPT", self.script.as_deref()),
            ("TENANT_ID", self.tenant_id.as_deref()),
            ("CLIENT_ID", self.client_id.as_deref()),
        ]
        .into_iter()
        .filter_map(|(suffix, opt)| opt.map(|v| (suffix, v)))
    }
}

// ---------------------------------------------------------------------------
// ConfigCredentialResolver
// ---------------------------------------------------------------------------

/// A credential resolver that merges config-file overrides with environment-variable fallbacks.
///
/// For each target, the resolver:
///
/// 1. Scans all env vars matching the target's prefix (same algorithm as
///    [`EnvCredentialResolver`]).
/// 2. Overlays any `Some` fields from the target's [`TargetEntry`] (config wins per key).
/// 3. Checks that all required suffixes for `kind` are present in the merged map. Missing keys are
///    reported as their **env var names** — the actionable hint for operators.
pub(crate) struct ConfigCredentialResolver {
    targets: HashMap<Uuid, TargetEntry>,
}

impl ConfigCredentialResolver {
    /// Create a new resolver with the given per-target config entries.
    pub(crate) fn new(targets: HashMap<Uuid, TargetEntry>) -> Self {
        Self { targets }
    }
}

#[async_trait]
impl CredentialResolver for ConfigCredentialResolver {
    async fn resolve(
        &self,
        target_system_id: Uuid,
        kind: TargetKind,
    ) -> Result<ResolvedCredentials, ResolveError> {
        let prefix = prefix_for(target_system_id);
        let required = required_suffixes(kind);

        // Step 1: collect all matching env vars.
        let mut creds = ResolvedCredentials::new();
        for (name, value) in std::env::vars() {
            if let Some(suffix) = name.strip_prefix(&prefix)
                && !suffix.is_empty()
            {
                creds.insert(suffix.to_string(), value);
            }
        }

        // Step 2: overlay config-file values (config wins per key).
        if let Some(entry) = self.targets.get(&target_system_id) {
            for (suffix, value) in entry.overrides() {
                creds.insert(suffix.to_string(), value.to_string());
            }
        }

        // Step 3: check required suffixes; report as env var names.
        let missing: Vec<String> = required
            .iter()
            .filter(|&&suffix| creds.get(suffix).is_none())
            .map(|&suffix| format!("{prefix}{suffix}"))
            .collect();

        if !missing.is_empty() {
            return Err(ResolveError::Missing(missing));
        }

        Ok(creds)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use super::*;
    use crate::{api::models::TargetKind, resolver::env::prefix_for};

    /// Run the `ConfigCredentialResolver` with a synthetic env by setting vars in the process
    /// environment.  Uses UUID namespacing to avoid collisions with concurrent tests.
    fn run_resolver_with_env(
        id: Uuid,
        kind: TargetKind,
        targets: HashMap<Uuid, TargetEntry>,
        vars: &HashMap<String, String>,
    ) -> Result<ResolvedCredentials, ResolveError> {
        for (k, v) in vars {
            // SAFETY: test-only; UUID-namespaced to avoid test collisions.
            unsafe { std::env::set_var(k, v) };
        }

        let resolver = ConfigCredentialResolver::new(targets);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = rt.block_on(resolver.resolve(id, kind));

        for k in vars.keys() {
            // SAFETY: test-only.
            unsafe { std::env::remove_var(k) };
        }

        result
    }

    // ── config-only custom script ─────────────────────────────────────────────

    #[test]
    fn config_only_custom_script_resolved() {
        let id = Uuid::new_v4();
        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: Some("/opt/scripts/rotate.sh".to_string()),
                tenant_id: None,
                client_id: None,
            },
        );
        // No env vars set for this ID.
        let creds = run_resolver_with_env(id, TargetKind::CustomScript, targets, &HashMap::new())
            .expect("config-only script should resolve");
        use bitwarden_sensitive_value::ExposeSensitive as _;
        let script_val = creds
            .get("SCRIPT")
            .expect("SCRIPT must be present")
            .expose();
        assert_eq!(**script_val, "/opt/scripts/rotate.sh");
    }

    // ── config tenant_id shadows env var ─────────────────────────────────────

    #[test]
    fn config_tenant_id_shadows_env_var() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                tenant_id: Some("config-tenant".to_string()),
                client_id: None,
            },
        );

        // Env has all three Entra vars; config overrides TENANT_ID.
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "env-tenant".to_string());
        vars.insert(format!("{prefix}CLIENT_ID"), "my-client".to_string());
        vars.insert(format!("{prefix}CLIENT_SECRET"), "my-secret".to_string());

        let creds = run_resolver_with_env(id, TargetKind::Entra, targets, &vars)
            .expect("should resolve with config override");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        let tenant = creds.get("TENANT_ID").expect("TENANT_ID present").expose();
        // Config wins over env.
        assert_eq!(**tenant, "config-tenant");

        // CLIENT_ID comes from env.
        let client = creds.get("CLIENT_ID").expect("CLIENT_ID present").expose();
        assert_eq!(**client, "my-client");

        // CLIENT_SECRET comes from env.
        assert!(creds.get("CLIENT_SECRET").is_some());
    }

    // ── env fallback when config absent ──────────────────────────────────────

    #[test]
    fn env_fallback_when_config_absent() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        // No TargetEntry for this UUID.
        let targets: HashMap<Uuid, TargetEntry> = HashMap::new();

        let mut vars = HashMap::new();
        vars.insert(
            format!("{prefix}SCRIPT"),
            "/usr/local/bin/rotate.sh".to_string(),
        );

        let creds = run_resolver_with_env(id, TargetKind::CustomScript, targets, &vars)
            .expect("env fallback should resolve");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        let script = creds.get("SCRIPT").expect("SCRIPT present").expose();
        assert_eq!(**script, "/usr/local/bin/rotate.sh");
    }

    // ── missing key reports env var name ─────────────────────────────────────

    #[test]
    fn missing_key_reports_env_var_name() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                tenant_id: Some("my-tenant".to_string()),
                client_id: None,
            },
        );

        // CLIENT_ID and CLIENT_SECRET not in env and not in config.
        let vars: HashMap<String, String> = HashMap::new();

        let err = run_resolver_with_env(id, TargetKind::Entra, targets, &vars)
            .expect_err("should fail with missing vars");

        match err {
            ResolveError::Missing(names) => {
                // Error must report the env var names (not some other format).
                assert!(
                    names.iter().any(|n| n == &format!("{prefix}CLIENT_ID")),
                    "must list CLIENT_ID env var: {names:?}"
                );
                assert!(
                    names.iter().any(|n| n == &format!("{prefix}CLIENT_SECRET")),
                    "must list CLIENT_SECRET env var: {names:?}"
                );
                // TENANT_ID was supplied via config — must NOT appear in missing.
                assert!(
                    !names.iter().any(|n| n.ends_with("TENANT_ID")),
                    "TENANT_ID was in config and must not be listed as missing: {names:?}"
                );
            }
        }
    }
}
