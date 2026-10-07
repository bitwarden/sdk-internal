//! Config-file-based credential resolver: `[targets.<uuid>]` entries win per key over the
//! target's environment variables. `client_secret` is env-only, since the config file is often
//! checked into a repo.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use uuid::Uuid;

use super::{CredentialResolver, ResolveError, ResolvedCredentials};
use crate::{
    api::models::TargetKind,
    resolver::env::{prefix_for, required_suffixes},
    sys::EnvSource,
};

/// Per-target overrides from the `[targets]` TOML section; each `Some` field shadows its
/// environment variable. There is no `client_secret` field, so secrets stay env-only.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetEntry {
    /// Path to the custom-script executable (`SCRIPT` suffix).
    pub(crate) script: Option<String>,
    /// How to launch the script (`SCRIPT_TYPE` suffix).
    pub(crate) script_type: Option<crate::integrations::scripting::ScriptType>,
    /// Azure AD tenant identifier (`TENANT_ID` suffix).
    pub(crate) tenant_id: Option<String>,
    /// Application (client) ID of the service principal (`CLIENT_ID` suffix).
    pub(crate) client_id: Option<String>,
}

impl TargetEntry {
    fn overrides(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("SCRIPT", self.script.as_deref()),
            ("SCRIPT_TYPE", self.script_type.map(|t| t.as_str())),
            ("TENANT_ID", self.tenant_id.as_deref()),
            ("CLIENT_ID", self.client_id.as_deref()),
        ]
        .into_iter()
        .filter_map(|(suffix, opt)| opt.map(|v| (suffix, v)))
    }
}

/// Merges config-file overrides over the target's environment variables, reporting a missing
/// required key by its env var name.
pub(crate) struct ConfigCredentialResolver {
    targets: HashMap<Uuid, TargetEntry>,
    env: Arc<dyn EnvSource>,
}

impl ConfigCredentialResolver {
    pub(crate) fn new(targets: HashMap<Uuid, TargetEntry>, env: Arc<dyn EnvSource>) -> Self {
        Self { targets, env }
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

        let mut creds = ResolvedCredentials::new();
        for (name, value) in self.env.vars() {
            if let Some(suffix) = name.strip_prefix(&prefix)
                && !suffix.is_empty()
            {
                creds.insert(suffix.to_string(), value);
            }
        }

        // Config-file values win per key.
        if let Some(entry) = self.targets.get(&target_system_id) {
            for (suffix, value) in entry.overrides() {
                creds.insert(suffix.to_string(), value.to_string());
            }
        }

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use super::*;
    use crate::{api::models::TargetKind, resolver::env::prefix_for, sys::FakeEnv};

    /// Runs the resolver against exactly `vars`; no process state is touched, so no lock is
    /// needed.
    fn run_resolver_with_env(
        id: Uuid,
        kind: TargetKind,
        targets: HashMap<Uuid, TargetEntry>,
        vars: &HashMap<String, String>,
    ) -> Result<ResolvedCredentials, ResolveError> {
        let env = vars
            .iter()
            .fold(FakeEnv::empty(), |env, (k, v)| env.with(k, v));
        let resolver = ConfigCredentialResolver::new(targets, Arc::new(env));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(resolver.resolve(id, kind))
    }

    #[test]
    fn config_only_custom_script_resolved() {
        let id = Uuid::new_v4();
        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: Some("/opt/scripts/rotate.sh".to_string()),
                script_type: None,
                tenant_id: None,
                client_id: None,
            },
        );
        let creds = run_resolver_with_env(id, TargetKind::CustomScript, targets, &HashMap::new())
            .expect("config-only script should resolve");
        use bitwarden_sensitive_value::ExposeSensitive as _;
        let script_val = creds
            .get("SCRIPT")
            .expect("SCRIPT must be present")
            .expose();
        assert_eq!(**script_val, "/opt/scripts/rotate.sh");
    }

    #[test]
    fn config_tenant_id_shadows_env_var() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: Some("config-tenant".to_string()),
                client_id: None,
            },
        );

        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "env-tenant".to_string());
        vars.insert(format!("{prefix}CLIENT_ID"), "my-client".to_string());
        vars.insert(format!("{prefix}CLIENT_SECRET"), "my-secret".to_string());

        let creds = run_resolver_with_env(id, TargetKind::Entra, targets, &vars)
            .expect("should resolve with config override");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        let tenant = creds.get("TENANT_ID").expect("TENANT_ID present").expose();
        assert_eq!(**tenant, "config-tenant");

        let client = creds.get("CLIENT_ID").expect("CLIENT_ID present").expose();
        assert_eq!(**client, "my-client");

        assert!(creds.get("CLIENT_SECRET").is_some());
    }

    #[test]
    fn env_fallback_when_config_absent() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

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

    #[test]
    fn missing_key_reports_env_var_name() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: Some("my-tenant".to_string()),
                client_id: None,
            },
        );

        let vars: HashMap<String, String> = HashMap::new();

        let err = run_resolver_with_env(id, TargetKind::Entra, targets, &vars)
            .expect_err("should fail with missing vars");

        match err {
            ResolveError::Missing(names) => {
                assert!(
                    names.iter().any(|n| n == &format!("{prefix}CLIENT_ID")),
                    "must list CLIENT_ID env var: {names:?}"
                );
                assert!(
                    names.iter().any(|n| n == &format!("{prefix}CLIENT_SECRET")),
                    "must list CLIENT_SECRET env var: {names:?}"
                );
                assert!(
                    !names.iter().any(|n| n.ends_with("TENANT_ID")),
                    "TENANT_ID was in config and must not be listed as missing: {names:?}"
                );
            }
        }
    }
}
