//! Config-file-based credential resolver: `[targets.<uuid>]` entries win per key over the
//! target's environment variables. `client_secret` and `bind_password` are env-only, since the
//! config file is often checked into a repo.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitwarden_pam_sealed::SealedTargetSystemKind;
use uuid::Uuid;

use super::{CredentialResolver, ResolveError, ResolvedCredentials};
use crate::{
    resolver::env::{
        BASE_DN_SUFFIX, BIND_DN_SUFFIX, CA_CERTIFICATE_SUFFIX, LDAP_HOST_SUFFIX, prefix_for,
        required_suffixes,
    },
    sys::EnvSource,
};

/// Per-target overrides from the `[targets]` TOML section; each `Some` field shadows its env var.
/// No `client_secret` or `bind_password` field, so secrets stay env-only.
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
    /// Host name of the Active Directory domain controller (`LDAP_HOST` suffix).
    pub(crate) ldap_host: Option<String>,
    /// DN of the delegated Active Directory service account (`BIND_DN` suffix).
    pub(crate) bind_dn: Option<String>,
    /// Search base DN for Active Directory account lookup (`BASE_DN` suffix).
    pub(crate) base_dn: Option<String>,
    /// PEM file of extra TLS trust anchors (`CA_CERTIFICATE` suffix); a path, so not env-only.
    pub(crate) ca_certificate: Option<String>,
}

impl TargetEntry {
    fn overrides(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("SCRIPT", self.script.as_deref()),
            ("SCRIPT_TYPE", self.script_type.map(|t| t.as_str())),
            ("TENANT_ID", self.tenant_id.as_deref()),
            ("CLIENT_ID", self.client_id.as_deref()),
            (LDAP_HOST_SUFFIX, self.ldap_host.as_deref()),
            (BIND_DN_SUFFIX, self.bind_dn.as_deref()),
            (BASE_DN_SUFFIX, self.base_dn.as_deref()),
            (CA_CERTIFICATE_SUFFIX, self.ca_certificate.as_deref()),
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
        kind: SealedTargetSystemKind,
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
    use crate::{resolver::env::prefix_for, sys::FakeEnv};

    /// Runs the resolver against exactly `vars`, touching no process state.
    fn run_resolver_with_env(
        id: Uuid,
        kind: SealedTargetSystemKind,
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
                ldap_host: None,
                bind_dn: None,
                base_dn: None,
                ca_certificate: None,
            },
        );
        let creds = run_resolver_with_env(
            id,
            SealedTargetSystemKind::CustomScript,
            targets,
            &HashMap::new(),
        )
        .expect("config-only script should resolve");
        use bitwarden_sensitive_value::ExposeSensitive as _;
        let script_val = creds
            .get("SCRIPT")
            .expect("SCRIPT must be present")
            .expose();
        assert_eq!(*script_val, "/opt/scripts/rotate.sh");
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
                ldap_host: None,
                bind_dn: None,
                base_dn: None,
                ca_certificate: None,
            },
        );

        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "env-tenant".to_string());
        vars.insert(format!("{prefix}CLIENT_ID"), "my-client".to_string());
        vars.insert(format!("{prefix}CLIENT_SECRET"), "my-secret".to_string());

        let creds = run_resolver_with_env(id, SealedTargetSystemKind::Entra, targets, &vars)
            .expect("should resolve with config override");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        let tenant = creds.get("TENANT_ID").expect("TENANT_ID present").expose();
        assert_eq!(*tenant, "config-tenant");

        let client = creds.get("CLIENT_ID").expect("CLIENT_ID present").expose();
        assert_eq!(*client, "my-client");

        assert!(creds.get("CLIENT_SECRET").is_some());
    }

    #[test]
    fn active_directory_config_keys_resolve_with_env_only_password() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: None,
                client_id: None,
                ldap_host: Some("dc01.corp.example".to_string()),
                bind_dn: Some("CN=svc-rotate,OU=Service Accounts,DC=corp,DC=example".to_string()),
                base_dn: Some("DC=corp,DC=example".to_string()),
                ca_certificate: None,
            },
        );

        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}BIND_PASSWORD"), "bind-secret".to_string());

        let creds =
            run_resolver_with_env(id, SealedTargetSystemKind::ActiveDirectory, targets, &vars)
                .expect("config host/DNs plus env password should resolve");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        assert_eq!(
            *creds.get("LDAP_HOST").expect("host").expose(),
            "dc01.corp.example"
        );
        assert_eq!(
            *creds.get("BASE_DN").expect("base dn").expose(),
            "DC=corp,DC=example"
        );
        assert!(creds.get("BIND_PASSWORD").is_some());
    }

    #[test]
    fn active_directory_bind_password_absent_is_reported_as_env_var() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: None,
                client_id: None,
                ldap_host: Some("dc01.corp.example".to_string()),
                bind_dn: Some("CN=svc-rotate,DC=corp,DC=example".to_string()),
                base_dn: Some("DC=corp,DC=example".to_string()),
                ca_certificate: None,
            },
        );

        let err = run_resolver_with_env(
            id,
            SealedTargetSystemKind::ActiveDirectory,
            targets,
            &HashMap::new(),
        )
        .expect_err("bind password cannot come from the config file");

        match err {
            ResolveError::Missing(names) => {
                assert_eq!(names, vec![format!("{prefix}BIND_PASSWORD")]);
            }
        }
    }

    #[test]
    fn active_directory_bind_password_in_config_is_an_unknown_field() {
        let toml_src = r#"
ldap_host = "dc01.corp.example"
bind_password = "should-not-be-accepted"
"#;
        let err = toml::from_str::<TargetEntry>(toml_src)
            .expect_err("bind_password must not be accepted in a [targets] entry");
        assert!(
            err.to_string().contains("unknown field `bind_password`"),
            "must be rejected as an unknown field: {err}"
        );
    }

    #[test]
    fn active_directory_ca_certificate_config_shadows_env() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: None,
                client_id: None,
                ldap_host: Some("dc01.corp.example".to_string()),
                bind_dn: Some("CN=svc-rotate,DC=corp,DC=example".to_string()),
                base_dn: Some("DC=corp,DC=example".to_string()),
                ca_certificate: Some("/etc/pki/from-config.pem".to_string()),
            },
        );

        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}BIND_PASSWORD"), "bind-secret".to_string());
        vars.insert(
            format!("{prefix}CA_CERTIFICATE"),
            "/etc/pki/from-env.pem".to_string(),
        );

        let creds =
            run_resolver_with_env(id, SealedTargetSystemKind::ActiveDirectory, targets, &vars)
                .expect("should resolve");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        assert_eq!(
            *creds.get("CA_CERTIFICATE").expect("ca cert").expose(),
            "/etc/pki/from-config.pem",
            "config must win over env for ca_certificate"
        );
    }

    #[test]
    fn active_directory_ca_certificate_falls_back_to_env() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut targets = HashMap::new();
        targets.insert(
            id,
            TargetEntry {
                script: None,
                script_type: None,
                tenant_id: None,
                client_id: None,
                ldap_host: Some("dc01.corp.example".to_string()),
                bind_dn: Some("CN=svc-rotate,DC=corp,DC=example".to_string()),
                base_dn: Some("DC=corp,DC=example".to_string()),
                ca_certificate: None,
            },
        );

        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}BIND_PASSWORD"), "bind-secret".to_string());
        vars.insert(
            format!("{prefix}CA_CERTIFICATE"),
            "/etc/pki/from-env.pem".to_string(),
        );

        let creds =
            run_resolver_with_env(id, SealedTargetSystemKind::ActiveDirectory, targets, &vars)
                .expect("should resolve");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        assert_eq!(
            *creds.get("CA_CERTIFICATE").expect("ca cert").expose(),
            "/etc/pki/from-env.pem"
        );
    }

    #[test]
    fn active_directory_ca_certificate_absent_from_both_sources() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);

        let mut vars = HashMap::new();
        vars.insert(
            format!("{prefix}LDAP_HOST"),
            "dc01.corp.example".to_string(),
        );
        vars.insert(format!("{prefix}BIND_DN"), "CN=svc,DC=corp".to_string());
        vars.insert(format!("{prefix}BASE_DN"), "DC=corp".to_string());
        vars.insert(format!("{prefix}BIND_PASSWORD"), "bind-secret".to_string());

        let creds = run_resolver_with_env(
            id,
            SealedTargetSystemKind::ActiveDirectory,
            HashMap::new(),
            &vars,
        )
        .expect("ca_certificate is optional");
        assert!(
            creds.get("CA_CERTIFICATE").is_none(),
            "an unset ca_certificate must stay unset"
        );
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

        let creds = run_resolver_with_env(id, SealedTargetSystemKind::CustomScript, targets, &vars)
            .expect("env fallback should resolve");

        use bitwarden_sensitive_value::ExposeSensitive as _;
        let script = creds.get("SCRIPT").expect("SCRIPT present").expose();
        assert_eq!(*script, "/usr/local/bin/rotate.sh");
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
                ldap_host: None,
                bind_dn: None,
                base_dn: None,
                ca_certificate: None,
            },
        );

        let vars: HashMap<String, String> = HashMap::new();

        let err = run_resolver_with_env(id, SealedTargetSystemKind::Entra, targets, &vars)
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

    #[test]
    fn entra_all_required_vars_present() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "my-tenant".to_string());
        vars.insert(format!("{prefix}CLIENT_ID"), "my-client".to_string());
        vars.insert(format!("{prefix}CLIENT_SECRET"), "my-secret".to_string());
        let creds = run_resolver_with_env(id, SealedTargetSystemKind::Entra, HashMap::new(), &vars)
            .unwrap();
        assert!(creds.get("TENANT_ID").is_some());
        assert!(creds.get("CLIENT_ID").is_some());
        assert!(creds.get("CLIENT_SECRET").is_some());
    }

    #[test]
    fn extra_vars_collected_into_map() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}SCRIPT"), "/bin/sh".to_string());
        vars.insert(format!("{prefix}OUT_PATH"), "/tmp/out.txt".to_string());
        let creds = run_resolver_with_env(
            id,
            SealedTargetSystemKind::CustomScript,
            HashMap::new(),
            &vars,
        )
        .unwrap();
        assert!(
            creds.get("OUT_PATH").is_some(),
            "extra var should be collected"
        );
    }

    #[test]
    fn entra_missing_all_reports_full_names() {
        let id: Uuid = "ec2c1d46-6a4b-4751-a310-af9601317f2d".parse().unwrap();
        let err = run_resolver_with_env(
            id,
            SealedTargetSystemKind::Entra,
            HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_err();
        match err {
            ResolveError::Missing(names) => {
                assert!(
                    names.contains(&"EC2C1D46_6A4B_4751_A310_AF9601317F2D_TENANT_ID".to_string()),
                    "must list TENANT_ID: {names:?}"
                );
                assert!(
                    names.contains(&"EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_ID".to_string()),
                    "must list CLIENT_ID: {names:?}"
                );
                assert!(
                    names.contains(
                        &"EC2C1D46_6A4B_4751_A310_AF9601317F2D_CLIENT_SECRET".to_string()
                    ),
                    "must list CLIENT_SECRET: {names:?}"
                );
            }
        }
    }

    #[test]
    fn custom_script_missing_script_var() {
        let id = Uuid::new_v4();
        let err = run_resolver_with_env(
            id,
            SealedTargetSystemKind::CustomScript,
            HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_err();
        let prefix = prefix_for(id);
        match err {
            ResolveError::Missing(names) => {
                assert!(
                    names.iter().any(|n| n == &format!("{prefix}SCRIPT")),
                    "must list SCRIPT var: {names:?}"
                );
            }
        }
    }

    #[test]
    fn partial_entra_missing_lists_only_absent() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "t".to_string());
        let err = run_resolver_with_env(id, SealedTargetSystemKind::Entra, HashMap::new(), &vars)
            .unwrap_err();
        match err {
            ResolveError::Missing(names) => {
                assert_eq!(names.len(), 2, "only 2 vars missing: {names:?}");
                assert!(names.iter().any(|n| n.ends_with("CLIENT_ID")));
                assert!(names.iter().any(|n| n.ends_with("CLIENT_SECRET")));
                assert!(!names.iter().any(|n| n.ends_with("TENANT_ID")));
            }
        }
    }

    #[test]
    fn active_directory_all_required_vars_present() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(
            format!("{prefix}LDAP_HOST"),
            "dc01.corp.example".to_string(),
        );
        vars.insert(
            format!("{prefix}BIND_DN"),
            "CN=svc-rotate,OU=Service Accounts,DC=corp,DC=example".to_string(),
        );
        vars.insert(format!("{prefix}BASE_DN"), "DC=corp,DC=example".to_string());
        vars.insert(format!("{prefix}BIND_PASSWORD"), "bind-secret".to_string());
        let creds = run_resolver_with_env(
            id,
            SealedTargetSystemKind::ActiveDirectory,
            HashMap::new(),
            &vars,
        )
        .unwrap();
        assert!(creds.get("LDAP_HOST").is_some());
        assert!(creds.get("BIND_DN").is_some());
        assert!(creds.get("BASE_DN").is_some());
        assert!(creds.get("BIND_PASSWORD").is_some());
    }

    #[test]
    fn active_directory_missing_all_lists_every_required_var() {
        let id = Uuid::new_v4();
        let err = run_resolver_with_env(
            id,
            SealedTargetSystemKind::ActiveDirectory,
            HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_err();
        let prefix = prefix_for(id);
        match err {
            ResolveError::Missing(names) => {
                assert!(names.iter().any(|n| n == &format!("{prefix}LDAP_HOST")));
                assert!(names.iter().any(|n| n == &format!("{prefix}BIND_DN")));
                assert!(names.iter().any(|n| n == &format!("{prefix}BASE_DN")));
                assert!(names.iter().any(|n| n == &format!("{prefix}BIND_PASSWORD")));
            }
        }
    }
}
