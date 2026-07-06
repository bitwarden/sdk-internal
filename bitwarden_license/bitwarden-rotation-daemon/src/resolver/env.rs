//! Environment-variable-based credential resolver.
//!
//! [`EnvCredentialResolver`] reads credentials from environment variables whose
//! names follow a well-known prefix scheme:
//!
//! ```text
//! <TARGET_ID_UPPER_UNDERSCORE>_<SUFFIX>
//! ```
//!
//! where `<TARGET_ID_UPPER_UNDERSCORE>` is the target system UUID uppercased
//! with hyphens replaced by underscores, and `<SUFFIX>` identifies the
//! credential (e.g. `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SCRIPT`).
//!
//! # Required suffixes per kind
//!
//! | Kind           | Required suffixes                              |
//! |----------------|------------------------------------------------|
//! | `Entra`        | `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`      |
//! | `CustomScript` | `SCRIPT`                                       |
//! | `Mssql`        | `HOST`, `USER`, `SECRET`                       |
//!
//! If any required variable is absent the resolver returns
//! [`ResolveError::Missing`] carrying the full variable names (safe to log
//! and report — names only, never values).
//!
//! Additional variables matching the prefix (beyond the required set) are
//! collected into the map and forwarded to the integration via
//! `ctx.creds.get("<SUFFIX>")`.

use async_trait::async_trait;
use uuid::Uuid;

use super::{CredentialResolver, ResolveError, ResolvedCredentials};
use crate::api::models::TargetKind;

/// Environment variable suffixes required per target kind.
fn required_suffixes(kind: TargetKind) -> &'static [&'static str] {
    match kind {
        TargetKind::Entra => &["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"],
        TargetKind::CustomScript => &["SCRIPT"],
        TargetKind::Mssql => &["HOST", "USER", "SECRET"],
        // Unknown kinds have no required suffixes; the executor will report
        // `unsupported_kind` before the resolver is invoked in practice.
        TargetKind::Unknown(_) => &[],
    }
}

/// Converts a target system UUID into the environment variable prefix.
///
/// Algorithm:
/// 1. Stringify the UUID (e.g. `"abc-1234-…"`).
/// 2. Uppercase.
/// 3. Replace `-` with `_`.
/// 4. Append a trailing `_`.
///
/// Result example: `"ABC_1234_…_"`.
pub(crate) fn prefix_for(id: Uuid) -> String {
    let mut s = id.to_string().to_uppercase();
    // Safety: replace is purely ASCII.
    s = s.replace('-', "_");
    s.push('_');
    s
}

/// A credential resolver that reads values from the process environment.
///
/// Thread-safe; constructed once and shared behind an `Arc`.
pub(crate) struct EnvCredentialResolver;

#[async_trait]
impl CredentialResolver for EnvCredentialResolver {
    async fn resolve(
        &self,
        target_system_id: Uuid,
        kind: TargetKind,
    ) -> Result<ResolvedCredentials, ResolveError> {
        let prefix = prefix_for(target_system_id);
        let required = required_suffixes(kind);

        let mut creds = ResolvedCredentials::new();
        let mut missing: Vec<String> = Vec::new();

        // Collect ALL matching env vars into the map.
        for (name, value) in std::env::vars() {
            if let Some(suffix) = name.strip_prefix(&prefix)
                && !suffix.is_empty()
            {
                creds.insert(suffix.to_string(), value);
            }
        }

        // Verify all required suffixes are present.
        for &suffix in required {
            if creds.get(suffix).is_none() {
                missing.push(format!("{prefix}{suffix}"));
            }
        }

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
    use crate::api::models::TargetKind;

    // Helper: run resolver with a synthetic env by setting vars in the process
    // environment under a mutex (std::env::set_var is not thread-safe in general;
    // tests that call this helper must not run concurrently with other env-mutating
    // tests).  We namespace by UUID so parallel crate tests don't collide.
    fn run_resolver_with_env(
        id: Uuid,
        kind: TargetKind,
        vars: &HashMap<String, String>,
    ) -> Result<ResolvedCredentials, ResolveError> {
        // Set vars.
        for (k, v) in vars {
            // SAFETY: test-only; single-threaded test runtime.
            unsafe { std::env::set_var(k, v) };
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = rt.block_on(EnvCredentialResolver.resolve(id, kind));

        // Unset vars.
        for k in vars.keys() {
            // SAFETY: test-only.
            unsafe { std::env::remove_var(k) };
        }

        result
    }

    // -----------------------------------------------------------------------
    // Prefix derivation
    // -----------------------------------------------------------------------

    #[test]
    fn prefix_plain_uuid() {
        let id: Uuid = "ec2c1d46-6a4b-4751-a310-af9601317f2d".parse().unwrap();
        assert_eq!(prefix_for(id), "EC2C1D46_6A4B_4751_A310_AF9601317F2D_");
    }

    #[test]
    fn prefix_hyphens_replaced_by_underscores() {
        let id: Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let p = prefix_for(id);
        assert!(!p.contains('-'), "hyphens must be replaced: {p}");
        assert!(p.ends_with('_'), "must have trailing underscore: {p}");
    }

    #[test]
    fn prefix_fully_uppercased() {
        let id: Uuid = "aabbccdd-eeff-1122-3344-556677889900".parse().unwrap();
        let p = prefix_for(id);
        // Every letter in the prefix must be uppercase.
        assert_eq!(p, p.to_uppercase(), "prefix must be all-uppercase: {p}");
    }

    // -----------------------------------------------------------------------
    // Successful resolution
    // -----------------------------------------------------------------------

    #[test]
    fn entra_all_required_vars_present() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}TENANT_ID"), "my-tenant".to_string());
        vars.insert(format!("{prefix}CLIENT_ID"), "my-client".to_string());
        vars.insert(format!("{prefix}CLIENT_SECRET"), "my-secret".to_string());
        let creds = run_resolver_with_env(id, TargetKind::Entra, &vars).unwrap();
        assert!(creds.get("TENANT_ID").is_some());
        assert!(creds.get("CLIENT_ID").is_some());
        assert!(creds.get("CLIENT_SECRET").is_some());
    }

    #[test]
    fn custom_script_script_var_present() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(
            format!("{prefix}SCRIPT"),
            "/usr/local/bin/rotate.sh".to_string(),
        );
        let creds = run_resolver_with_env(id, TargetKind::CustomScript, &vars).unwrap();
        assert!(creds.get("SCRIPT").is_some());
    }

    #[test]
    fn extra_vars_collected_into_map() {
        let id = Uuid::new_v4();
        let prefix = prefix_for(id);
        let mut vars = HashMap::new();
        vars.insert(format!("{prefix}SCRIPT"), "/bin/sh".to_string());
        vars.insert(format!("{prefix}OUT_PATH"), "/tmp/out.txt".to_string());
        let creds = run_resolver_with_env(id, TargetKind::CustomScript, &vars).unwrap();
        assert!(
            creds.get("OUT_PATH").is_some(),
            "extra var should be collected"
        );
    }

    // -----------------------------------------------------------------------
    // Missing-var listing
    // -----------------------------------------------------------------------

    #[test]
    fn entra_missing_all_reports_full_names() {
        let id: Uuid = "ec2c1d46-6a4b-4751-a310-af9601317f2d".parse().unwrap();
        // Ensure the vars are not set (no prefix match).
        let err = run_resolver_with_env(id, TargetKind::Entra, &HashMap::new()).unwrap_err();
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
        let err = run_resolver_with_env(id, TargetKind::CustomScript, &HashMap::new()).unwrap_err();
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
        // CLIENT_ID and CLIENT_SECRET missing.
        let err = run_resolver_with_env(id, TargetKind::Entra, &vars).unwrap_err();
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
    fn mssql_missing_all_lists_host_user_secret() {
        let id = Uuid::new_v4();
        let err = run_resolver_with_env(id, TargetKind::Mssql, &HashMap::new()).unwrap_err();
        let prefix = prefix_for(id);
        match err {
            ResolveError::Missing(names) => {
                assert!(names.iter().any(|n| n == &format!("{prefix}HOST")));
                assert!(names.iter().any(|n| n == &format!("{prefix}USER")));
                assert!(names.iter().any(|n| n == &format!("{prefix}SECRET")));
            }
        }
    }
}
