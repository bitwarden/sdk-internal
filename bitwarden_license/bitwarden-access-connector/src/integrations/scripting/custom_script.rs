//! The `CustomScript` integration driver.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;

use super::{
    super::{Integration, IntegrationError, RotateContext},
    CommandSpec, InvokeError, ScriptRunner, ScriptType, classify_outcome, payload_json, powershell,
    resolve_script_path, resolve_script_type,
};
use crate::sys::Platform;

pub(crate) struct CustomScriptIntegration {
    /// The script root.
    pub(crate) script_root: Option<PathBuf>,
    /// Maximum time to wait for the script to complete.
    pub(crate) timeout: Duration,
    /// Explicit PowerShell host path; `None` discovers one on `PATH`.
    pub(crate) powershell_path: Option<PathBuf>,
    /// `-ExecutionPolicy` value passed to the PowerShell host.
    pub(crate) powershell_execution_policy: String,
    /// Where host discovery and the environment allowlist read from.
    pub(crate) platform: Platform,
    /// What actually executes the script.
    pub(crate) runner: Arc<dyn ScriptRunner>,
}

impl CustomScriptIntegration {
    pub(crate) fn new(
        script_root: Option<PathBuf>,
        timeout: Duration,
        powershell_path: Option<PathBuf>,
        powershell_execution_policy: String,
        platform: Platform,
        runner: Arc<dyn ScriptRunner>,
    ) -> Self {
        Self {
            script_root,
            timeout,
            powershell_path,
            powershell_execution_policy,
            platform,
            runner,
        }
    }

    fn build_command(
        &self,
        script_path: &Path,
        script_type: ScriptType,
        operation: &str,
    ) -> Result<CommandSpec, InvokeError> {
        match script_type {
            ScriptType::Direct => Ok(CommandSpec {
                program: script_path.to_path_buf(),
                args: vec![operation.into()],
                env: Vec::new(),
            }),
            ScriptType::Powershell => powershell::build_command(
                self.powershell_path.as_deref(),
                script_path,
                operation,
                &self.powershell_execution_policy,
                &self.platform,
            ),
        }
    }

    async fn invoke(
        &self,
        script_path: &Path,
        script_type: ScriptType,
        operation: &str,
        ctx: &RotateContext,
        new_password: Option<&str>,
    ) -> Result<Option<i32>, InvokeError> {
        let payload = payload_json(operation, ctx, new_password)?;
        let spec = self.build_command(script_path, script_type, operation)?;
        self.runner.run(spec, &payload, self.timeout).await
    }

    async fn run_operation(
        &self,
        script_path: &Path,
        script_type: ScriptType,
        operation: &str,
        ctx: &RotateContext,
        new_password: Option<&str>,
    ) -> Result<(), IntegrationError> {
        let outcome = self
            .invoke(script_path, script_type, operation, ctx, new_password)
            .await;
        classify_outcome(outcome, operation, self.timeout.as_secs())
    }
}

#[async_trait]
impl Integration for CustomScriptIntegration {
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(
            &ctx.creds,
            self.script_root.as_deref(),
            self.platform.fs.as_ref(),
        )?;
        let script_type = resolve_script_type(&ctx.creds, &script)?;
        let pw = ctx.new_password.as_str();
        self.run_operation(&script, script_type, "rotate", ctx, Some(pw))
            .await
    }

    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(
            &ctx.creds,
            self.script_root.as_deref(),
            self.platform.fs.as_ref(),
        )?;
        let script_type = resolve_script_type(&ctx.creds, &script)?;
        let pw = ctx.new_password.as_str();
        self.run_operation(&script, script_type, "verify", ctx, Some(pw))
            .await
    }

    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(
            &ctx.creds,
            self.script_root.as_deref(),
            self.platform.fs.as_ref(),
        )?;
        let script_type = resolve_script_type(&ctx.creds, &script)?;
        // newPassword is OMITTED for terminate (script has no need for it; withholding
        // it prevents accidental echo in any script-side logging).
        self.run_operation(&script, script_type, "terminate", ctx, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use chrono::Utc;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        error::{ErrorClass, FailureCode},
        integrations::{TargetEffect, scripting::RecordingRunner},
        resolver::ResolvedCredentials,
        sys::{FakeEnv, FakeFs, Platform},
    };

    /// Paths are never touched here: `build_command` and `run_operation` take the script path
    /// as given, and only the public `rotate`/`verify`/`terminate_sessions` entry points
    /// canonicalise. Those are covered by `tests/scripting_integration.rs`.
    const SH_SCRIPT: &str = "/opt/bwrd/rotate.sh";
    const PS_SCRIPT: &str = "/opt/bwrd/rotate.ps1";
    const HOST: &str = "/usr/local/bin/pwsh";

    fn ctx_with(creds: ResolvedCredentials) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: Zeroizing::new("super-secret-pw-SENTINEL".to_string()),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn ctx() -> RotateContext {
        ctx_with(ResolvedCredentials::new())
    }

    /// An integration with both seams faked and a PowerShell host pinned, so no discovery and
    /// no process ever happens.
    fn integration(env: FakeEnv, runner: Arc<RecordingRunner>) -> CustomScriptIntegration {
        CustomScriptIntegration::new(
            None,
            Duration::from_secs(30),
            Some(PathBuf::from(HOST)),
            "Bypass".to_string(),
            Platform::fake(env, FakeFs::empty()),
            runner,
        )
    }

    fn args_of(spec: &CommandSpec) -> Vec<String> {
        spec.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn direct_launcher_executes_the_script_itself_with_no_environment() {
        let integ = integration(FakeEnv::empty(), Arc::new(RecordingRunner::exiting(0)));
        let spec = integ
            .build_command(Path::new(SH_SCRIPT), ScriptType::Direct, "rotate")
            .unwrap();

        assert_eq!(spec.program, PathBuf::from(SH_SCRIPT));
        assert_eq!(args_of(&spec), vec!["rotate"]);
        assert!(
            spec.env.is_empty(),
            "a directly executed script inherits nothing: {:?}",
            spec.env
        );
    }

    #[test]
    fn powershell_launcher_runs_the_host_with_file() {
        let integ = integration(FakeEnv::empty(), Arc::new(RecordingRunner::exiting(0)));
        let spec = integ
            .build_command(Path::new(PS_SCRIPT), ScriptType::Powershell, "rotate")
            .unwrap();

        assert_eq!(spec.program, PathBuf::from(HOST));
        assert_eq!(
            args_of(&spec),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                PS_SCRIPT,
                "rotate",
            ]
        );
    }

    #[test]
    fn powershell_launcher_forwards_the_allowlist_and_nothing_else() {
        // The credential and the daemon token exist in the environment the daemon reads; only
        // the allowlisted names may reach the child.
        let env = FakeEnv::from([
            ("PATH", "/usr/bin"),
            ("BWRD_TOKEN", "SENTINEL_TOKEN"),
            (
                "A1B2C3D4_0000_0000_0000_000000000001_CLIENT_SECRET",
                "SENTINEL_SECRET",
            ),
        ]);
        let integ = integration(env, Arc::new(RecordingRunner::exiting(0)));
        let spec = integ
            .build_command(Path::new(PS_SCRIPT), ScriptType::Powershell, "rotate")
            .unwrap();

        let names: Vec<String> = spec
            .env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["PATH"], "only PATH is allowlisted here");

        let flattened = format!("{:?}", spec.env);
        assert!(!flattened.contains("SENTINEL_TOKEN"), "{flattened}");
        assert!(!flattened.contains("SENTINEL_SECRET"), "{flattened}");
    }

    #[test]
    fn powershell_launcher_without_any_host_is_fatal() {
        // No configured host and an environment with no PATH to search.
        let integ = CustomScriptIntegration::new(
            None,
            Duration::from_secs(30),
            None,
            "Bypass".to_string(),
            Platform::blank(),
            Arc::new(RecordingRunner::exiting(0)),
        );

        let err = integ
            .build_command(Path::new(PS_SCRIPT), ScriptType::Powershell, "rotate")
            .unwrap_err();
        assert_eq!(err, InvokeError::HostNotFound);
    }

    #[tokio::test]
    async fn payload_carries_the_operation_and_identity() {
        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(FakeEnv::empty(), runner.clone());

        integ
            .run_operation(
                Path::new(SH_SCRIPT),
                ScriptType::Direct,
                "rotate",
                &ctx(),
                Some("new-pw"),
            )
            .await
            .unwrap();

        let payload = runner.only_payload();
        assert_eq!(payload["operation"], "rotate");
        assert_eq!(payload["targetSystemId"], Uuid::nil().to_string().as_str());
        assert_eq!(payload["accountIdentity"], "user@example.com");
        assert_eq!(payload["newPassword"], "new-pw");
    }

    #[tokio::test]
    async fn payload_omits_new_password_for_terminate() {
        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(FakeEnv::empty(), runner.clone());

        integ
            .run_operation(
                Path::new(SH_SCRIPT),
                ScriptType::Direct,
                "terminate",
                &ctx(),
                None,
            )
            .await
            .unwrap();

        let payload = runner.only_payload();
        assert_eq!(payload["operation"], "terminate");
        assert!(
            payload.get("newPassword").is_none(),
            "newPassword must be absent for terminate: {payload}"
        );
    }

    #[tokio::test]
    async fn payload_excludes_the_keys_that_configure_the_daemon() {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT".to_string(), SH_SCRIPT.to_string());
        creds.insert("SCRIPT_TYPE".to_string(), "direct".to_string());
        creds.insert("OUT_PATH".to_string(), "/tmp/out".to_string());

        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(FakeEnv::empty(), runner.clone());

        integ
            .run_operation(
                Path::new(SH_SCRIPT),
                ScriptType::Direct,
                "rotate",
                &ctx_with(creds),
                Some("pw"),
            )
            .await
            .unwrap();

        let payload = runner.only_payload();
        assert!(payload["credentials"].get("SCRIPT").is_none());
        assert!(payload["credentials"].get("SCRIPT_TYPE").is_none());
        assert!(
            payload["credentials"].get("OUT_PATH").is_some(),
            "unrelated credentials are still forwarded: {payload}"
        );
    }

    async fn outcome_of(runner: RecordingRunner, operation: &str) -> Result<(), IntegrationError> {
        let integ = integration(FakeEnv::empty(), Arc::new(runner));
        integ
            .run_operation(
                Path::new(SH_SCRIPT),
                ScriptType::Direct,
                operation,
                &ctx(),
                Some("pw"),
            )
            .await
    }

    #[tokio::test]
    async fn exit_codes_map_to_sync_state() {
        outcome_of(RecordingRunner::exiting(0), "rotate")
            .await
            .unwrap();

        for (code, class, effect) in [
            (1, ErrorClass::Fatal, TargetEffect::NotApplied),
            (2, ErrorClass::Fatal, TargetEffect::Applied),
            (3, ErrorClass::Fatal, TargetEffect::Unknown),
            (4, ErrorClass::Transient, TargetEffect::NotApplied),
            (99, ErrorClass::Fatal, TargetEffect::Unknown),
        ] {
            let err = outcome_of(RecordingRunner::exiting(code), "rotate")
                .await
                .unwrap_err();
            assert_eq!(err.class, class, "exit {code}");
            assert_eq!(err.effect, effect, "exit {code}");
        }

        // An unknown code means "unknown" only for rotate; nothing else can have changed the
        // credential.
        let err = outcome_of(RecordingRunner::exiting(99), "verify")
            .await
            .unwrap_err();
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[tokio::test]
    async fn timeout_effect_depends_on_the_operation() {
        for (operation, effect) in [
            ("rotate", TargetEffect::Unknown),
            ("verify", TargetEffect::Applied),
            ("terminate", TargetEffect::NotApplied),
        ] {
            let err = outcome_of(RecordingRunner::failing(InvokeError::Timeout), operation)
                .await
                .unwrap_err();
            assert_eq!(err.code, FailureCode::ScriptTimeout, "{operation}");
            assert_eq!(err.effect, effect, "{operation}");
        }
    }
}
