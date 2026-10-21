//! Rotation through an operator-supplied script, run directly or through a PowerShell host.
//!
//! [`CustomScriptIntegration`] runs the target's script once per [`Operation`], passing the
//! operation name as its only argument and a JSON payload on stdin. Each run has four steps:
//!
//! 1. **Resolve** ([`command`]): the `SCRIPT` credential becomes a canonical path, confined to the
//!    script root when one is configured. `SCRIPT_TYPE`, or else the file extension, picks the
//!    [`ScriptType`].
//! 2. **Build** ([`command`]): the script and its type become a
//!    [`CommandSpec`](command::CommandSpec), a plain value naming the program, its arguments and
//!    its complete environment. A PowerShell script runs as an argument to a discovered or
//!    configured host.
//! 3. **Run** ([`runner`]): a [`ScriptRunner`] spawns the process, writes the payload and waits for
//!    it to exit, killing it at the timeout. Tests substitute a recording runner, so nothing is
//!    spawned.
//! 4. **Classify** ([`outcome`]): the exit code, signal or invocation error becomes success or an
//!    [`IntegrationError`].
//!
//! A configuration problem in the first two steps fails with `credentials_unresolved` before
//! anything runs, so the target is reported unchanged.
//!
//! # Secrets
//!
//! The new password and the target's credentials reach the script only through the stdin
//! payload. Argv carries just the operation name. A directly executed script starts with an empty
//! environment, and a PowerShell host gets only a fixed allowlist of system variables. The
//! script's stdout and stderr go to the null device, since either could echo what it was given.
//! The payload omits `newPassword` for `terminate`, and never includes `SCRIPT` or `SCRIPT_TYPE`,
//! which configure the connector rather than the target.
//!
//! # Target effect
//!
//! Exit codes 1 to 4 report what happened to the target. When the script ends without one of
//! them (an exit code outside the contract, a signal, a broken pipe, or the timeout), the effect
//! is inferred from the operation: only `rotate` can have changed the credential, so it reports
//! [`TargetEffect::Unknown`] and the others report [`TargetEffect::NotApplied`]. The exception
//! is a `verify` that times out, which reports [`TargetEffect::Applied`]: it only runs after a
//! successful `rotate`. See [`Operation::effect_if_interrupted`] and
//! [`Operation::effect_on_timeout`].
//!
//! The operator-facing contract (argv, stdin payload, exit codes, timeouts, PowerShell launching)
//! is documented in the crate README under `## Custom-script integration` and
//! `## PowerShell scripts`.

mod command;
mod outcome;
mod runner;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitwarden_pam::RotationFailureCode;
use serde::Serialize;

pub(crate) use self::command::ScriptType;
use self::{
    command::{build_command, resolve_script_path, resolve_script_type},
    outcome::classify_outcome,
    runner::{InvokeError, ScriptRunner},
};
use super::{Integration, IntegrationError, RotateContext, TargetEffect};
use crate::{
    error::{Retry, SafeDetail},
    sys::Platform,
};

/// The operation a script is asked to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Change the account's password to the new one.
    Rotate,
    /// Check that the account accepts the new password.
    Verify,
    /// End the account's existing sessions.
    Terminate,
}

impl Operation {
    /// The script's argv operand and the payload's `operation` value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::Verify => "verify",
            Self::Terminate => "terminate",
        }
    }

    /// The target's state when the script ended without a result the contract defines: only a
    /// rotate may have changed it.
    pub(crate) fn effect_if_interrupted(self) -> TargetEffect {
        match self {
            Self::Rotate => TargetEffect::Unknown,
            Self::Verify | Self::Terminate => TargetEffect::NotApplied,
        }
    }

    /// The target's state when the script was killed for exceeding its timeout.
    pub(crate) fn effect_on_timeout(self) -> TargetEffect {
        match self {
            Self::Rotate => TargetEffect::Unknown,
            Self::Verify => TargetEffect::Applied,
            Self::Terminate => TargetEffect::NotApplied,
        }
    }
}

/// How PowerShell scripts are launched.
pub(crate) struct PowershellConfig {
    /// Explicit PowerShell host path; `None` discovers one on `PATH`.
    pub(crate) host: Option<PathBuf>,
    /// Value of the host's `-ExecutionPolicy` argument.
    pub(crate) execution_policy: String,
}

/// Runs an operator-supplied script for each rotation operation.
pub(crate) struct CustomScriptIntegration {
    /// Directory the script must resolve into; `None` allows any path.
    pub(crate) script_root: Option<PathBuf>,
    /// How long a script may run before it is killed.
    pub(crate) timeout: Duration,
    pub(crate) powershell: PowershellConfig,
    /// Where host discovery, the environment allowlist and path resolution read from.
    pub(crate) platform: Platform,
    pub(crate) runner: Arc<dyn ScriptRunner>,
}

impl CustomScriptIntegration {
    async fn run(&self, ctx: &RotateContext, op: Operation) -> Result<(), IntegrationError> {
        let script = resolve_script_path(
            &ctx.creds,
            self.script_root.as_deref(),
            self.platform.fs.as_ref(),
        )?;
        let script_type = resolve_script_type(&ctx.creds, &script)?;

        let spec = build_command(&script, script_type, op, &self.powershell, &self.platform)?;
        let outcome = match payload_json(op, ctx) {
            Ok(payload) => self.runner.run(spec, &payload, self.timeout).await,
            Err(e) => Err(e),
        };
        classify_outcome(outcome, op, self.timeout.as_secs())
    }
}

#[async_trait]
impl Integration for CustomScriptIntegration {
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        self.run(ctx, Operation::Rotate).await
    }

    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        self.run(ctx, Operation::Verify).await
    }

    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        self.run(ctx, Operation::Terminate).await
    }
}

/// A failure caused by missing or invalid operator configuration; nothing ran, so the target is
/// untouched.
fn misconfigured(kind: &'static str) -> IntegrationError {
    IntegrationError {
        retry: Retry::Permanent,
        effect: TargetEffect::NotApplied,
        code: RotationFailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind(kind),
    }
}

/// The JSON document written to the script's stdin.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptPayload<'a> {
    operation: &'a str,
    target_system_id: &'a uuid::Uuid,
    account_identity: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_password: Option<&'a str>,
    credentials: HashMap<&'a str, &'a str>,
}

/// Serializes the stdin payload for `operation`.
fn payload_json(operation: Operation, ctx: &RotateContext) -> Result<Vec<u8>, InvokeError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    // Terminate gets no new password, so script-side logging cannot echo it.
    let new_password = match operation {
        Operation::Rotate | Operation::Verify => Some(ctx.new_password.as_str()),
        Operation::Terminate => None,
    };

    // SCRIPT and SCRIPT_TYPE configure the connector's own invocation, not the target, so the
    // script does not get them.
    let mut credentials: HashMap<&str, &str> = HashMap::new();
    for (k, v) in ctx.creds.iter() {
        if k != "SCRIPT" && k != "SCRIPT_TYPE" {
            credentials.insert(k.as_str(), v.expose().as_ref() as &str);
        }
    }

    let payload = ScriptPayload {
        operation: operation.as_str(),
        target_system_id: &ctx.target_system_id,
        account_identity: &ctx.account_identity,
        new_password,
        credentials,
    };

    serde_json::to_vec(&payload).map_err(|_| InvokeError::Serialize)
}

#[cfg(test)]
mod tests {
    use bitwarden_pam::RotationFailureCode;
    use chrono::Utc;
    use uuid::Uuid;

    use super::{runner::RecordingRunner, *};
    use crate::{
        resolver::ResolvedCredentials,
        sys::{FakeEnv, FakeFs},
    };

    const SH_SCRIPT: &str = "/opt/bwac/rotate.sh";
    const HOST: &str = "/usr/local/bin/pwsh";

    fn ctx_with(mut creds: ResolvedCredentials) -> RotateContext {
        if creds.get("SCRIPT").is_none() {
            creds.insert("SCRIPT".to_string(), SH_SCRIPT.to_string());
        }
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: "super-secret-pw-SENTINEL".to_string(),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn ctx() -> RotateContext {
        ctx_with(ResolvedCredentials::new())
    }

    /// Both seams faked, the script present and a PowerShell host pinned: no discovery, no
    /// process.
    fn integration(runner: Arc<RecordingRunner>) -> CustomScriptIntegration {
        CustomScriptIntegration {
            script_root: None,
            timeout: Duration::from_secs(30),
            powershell: PowershellConfig {
                host: Some(PathBuf::from(HOST)),
                execution_policy: "Bypass".to_string(),
            },
            platform: Platform::fake(FakeEnv::empty(), FakeFs::empty().with_file(SH_SCRIPT)),
            runner,
        }
    }

    #[test]
    fn operation_names_are_the_contract_spellings() {
        assert_eq!(Operation::Rotate.as_str(), "rotate");
        assert_eq!(Operation::Verify.as_str(), "verify");
        assert_eq!(Operation::Terminate.as_str(), "terminate");
    }

    #[tokio::test]
    async fn payload_carries_the_operation_and_identity() {
        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(runner.clone());

        integ.run(&ctx(), Operation::Rotate).await.unwrap();

        let payload = runner.only_payload();
        assert_eq!(payload["operation"], "rotate");
        assert_eq!(payload["targetSystemId"], Uuid::nil().to_string().as_str());
        assert_eq!(payload["accountIdentity"], "user@example.com");
        assert_eq!(payload["newPassword"], "super-secret-pw-SENTINEL");
    }

    #[tokio::test]
    async fn payload_carries_new_password_for_verify() {
        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(runner.clone());

        integ.run(&ctx(), Operation::Verify).await.unwrap();

        let payload = runner.only_payload();
        assert_eq!(payload["operation"], "verify");
        assert_eq!(payload["newPassword"], "super-secret-pw-SENTINEL");
    }

    #[tokio::test]
    async fn payload_omits_new_password_for_terminate() {
        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(runner.clone());

        integ.run(&ctx(), Operation::Terminate).await.unwrap();

        let payload = runner.only_payload();
        assert_eq!(payload["operation"], "terminate");
        assert!(
            payload.get("newPassword").is_none(),
            "newPassword must be absent for terminate: {payload}"
        );
    }

    #[tokio::test]
    async fn payload_excludes_the_keys_that_configure_the_connector() {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT".to_string(), SH_SCRIPT.to_string());
        creds.insert("SCRIPT_TYPE".to_string(), "direct".to_string());
        creds.insert("OUT_PATH".to_string(), "/tmp/out".to_string());

        let runner = Arc::new(RecordingRunner::exiting(0));
        let integ = integration(runner.clone());

        integ
            .run(&ctx_with(creds), Operation::Rotate)
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

    async fn outcome_of(
        runner: RecordingRunner,
        operation: Operation,
    ) -> Result<(), IntegrationError> {
        integration(Arc::new(runner)).run(&ctx(), operation).await
    }

    #[tokio::test]
    async fn exit_codes_map_to_sync_state() {
        outcome_of(RecordingRunner::exiting(0), Operation::Rotate)
            .await
            .unwrap();

        for (code, retry, effect) in [
            (1, Retry::Permanent, TargetEffect::NotApplied),
            (2, Retry::Permanent, TargetEffect::Applied),
            (3, Retry::Permanent, TargetEffect::Unknown),
            (4, Retry::Transient, TargetEffect::NotApplied),
            (99, Retry::Permanent, TargetEffect::Unknown),
        ] {
            let err = outcome_of(RecordingRunner::exiting(code), Operation::Rotate)
                .await
                .unwrap_err();
            assert_eq!(err.retry, retry, "exit {code}");
            assert_eq!(err.effect, effect, "exit {code}");
        }

        // An unknown code means "unknown" only for rotate; nothing else can have changed the
        // credential.
        let err = outcome_of(RecordingRunner::exiting(99), Operation::Verify)
            .await
            .unwrap_err();
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[tokio::test]
    async fn timeout_effect_depends_on_the_operation() {
        for (operation, effect) in [
            (Operation::Rotate, TargetEffect::Unknown),
            (Operation::Verify, TargetEffect::Applied),
            (Operation::Terminate, TargetEffect::NotApplied),
        ] {
            let err = outcome_of(RecordingRunner::failing(InvokeError::Timeout), operation)
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                RotationFailureCode::ScriptTimeout,
                "{operation:?}"
            );
            assert_eq!(err.effect, effect, "{operation:?}");
        }
    }
}
