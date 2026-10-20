//! Rotation through an operator-supplied script, run directly or through a PowerShell host.
//!
//! Both launchers share the contract documented in the crate README: secrets travel only on
//! stdin, and `classify_outcome` maps exit codes to outcomes.

pub(crate) mod custom_script;
pub(crate) mod powershell;

use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use bitwarden_pam::RotationFailureCode;
use serde::Serialize;
use tokio::{process::Command, time};

use super::{IntegrationError, RotateContext, TargetEffect};
use crate::{
    error::{ErrorClass, SafeDetail},
    resolver::ResolvedCredentials,
    sys::FileSystem,
};

/// How the connector launches an operator-supplied script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScriptType {
    /// Execute the file itself, relying on a shebang or the executable bit.
    Direct,
    /// Launch the file through a PowerShell host. The default for a `.ps1`.
    Powershell,
}

impl ScriptType {
    /// Parses an operator-supplied `SCRIPT_TYPE` value, or `None` if it names no known type.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Self::Direct),
            "powershell" => Some(Self::Powershell),
            _ => None,
        }
    }

    /// The config spelling of this variant.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Powershell => "powershell",
        }
    }

    /// The launcher for `script`: `explicit` when set, otherwise PowerShell for a `.ps1`.
    pub(crate) fn detect(script: &Path, explicit: Option<ScriptType>) -> Self {
        if let Some(explicit) = explicit {
            return explicit;
        }
        match script.extension() {
            Some(ext) if ext.eq_ignore_ascii_case("ps1") => Self::Powershell,
            _ => Self::Direct,
        }
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

pub(crate) fn payload_json(
    operation: &str,
    ctx: &RotateContext,
    new_password: Option<&str>,
) -> Result<Vec<u8>, InvokeError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    // SCRIPT and SCRIPT_TYPE configure the connector's own invocation, not the target, so the
    // script does not get them.
    let mut credentials: HashMap<&str, &str> = HashMap::new();
    for (k, v) in ctx.creds.iter() {
        if k != "SCRIPT" && k != "SCRIPT_TYPE" {
            credentials.insert(k.as_str(), v.expose().as_ref() as &str);
        }
    }

    let payload = ScriptPayload {
        operation,
        target_system_id: &ctx.target_system_id,
        account_identity: &ctx.account_identity,
        new_password,
        credentials,
    };

    serde_json::to_vec(&payload).map_err(|_| InvokeError::Serialize)
}

pub(crate) fn resolve_script_path(
    creds: &ResolvedCredentials,
    script_root: Option<&Path>,
    fs: &dyn FileSystem,
) -> Result<PathBuf, IntegrationError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    let script_val = creds.get("SCRIPT").ok_or_else(|| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: RotationFailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind("MissingScript"),
    })?;

    let script_str = script_val.expose();
    let raw_path = PathBuf::from(script_str.as_ref() as &str);

    let canonical = fs.canonicalize(&raw_path).map_err(|_| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: RotationFailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind("ScriptNotFound"),
    })?;

    if let Some(root) = script_root {
        let canonical_root = fs.canonicalize(root).map_err(|_| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: RotationFailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind("ScriptRootInvalid"),
        })?;

        if !canonical.starts_with(&canonical_root) {
            return Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::NotApplied,
                code: RotationFailureCode::CredentialsUnresolved,
                detail: SafeDetail::from_kind("ScriptOutsideRoot"),
            });
        }
    }

    Ok(canonical)
}

pub(crate) fn resolve_script_type(
    creds: &ResolvedCredentials,
    script: &Path,
) -> Result<ScriptType, IntegrationError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    let explicit = match creds.get("SCRIPT_TYPE") {
        Some(value) => {
            let exposed = value.expose();
            Some(
                ScriptType::parse(exposed.as_ref() as &str).ok_or_else(|| IntegrationError {
                    class: ErrorClass::Fatal,
                    effect: TargetEffect::NotApplied,
                    code: RotationFailureCode::CredentialsUnresolved,
                    detail: SafeDetail::from_kind("UnknownScriptType"),
                })?,
            )
        }
        None => None,
    };

    Ok(ScriptType::detect(script, explicit))
}

/// Internal errors from script invocation, translated by [`classify_outcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvokeError {
    Serialize,
    Spawn,
    StdinWrite,
    Wait,
    Timeout,
    /// No PowerShell host could be found and none was configured.
    HostNotFound,
}

/// A process to run, as a plain value: no OS handles and no ambient state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandSpec {
    pub(crate) program: PathBuf,
    /// Arguments, excluding the program name.
    pub(crate) args: Vec<OsString>,
    /// The child's complete environment; nothing is inherited.
    pub(crate) env: Vec<(OsString, OsString)>,
}

/// How a script process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptExit {
    /// The process exited with this code.
    Code(i32),
    /// A signal ended the process, with its number when the platform reports one.
    Signal(Option<i32>),
}

impl From<std::process::ExitStatus> for ScriptExit {
    fn from(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Code(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            Self::Signal(status.signal())
        }
        #[cfg(not(unix))]
        Self::Signal(None)
    }
}

/// Runs a [`CommandSpec`] and reports how it exited.
#[async_trait]
pub(crate) trait ScriptRunner: Send + Sync {
    /// Runs `spec` with `payload` on stdin and returns how it exited.
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<ScriptExit, InvokeError>;
}

/// Runs scripts as real child processes.
pub(crate) struct ProcessScriptRunner;

#[async_trait]
impl ScriptRunner for ProcessScriptRunner {
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<ScriptExit, InvokeError> {
        use tokio::io::AsyncWriteExt as _;

        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)));

        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| InvokeError::Spawn)?;

        let run = async {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(payload)
                    .await
                    .map_err(|_| InvokeError::StdinWrite)?;
            }
            child.wait().await.map_err(|_| InvokeError::Wait)
        };

        match time::timeout(timeout, run).await {
            Ok(Ok(status)) => Ok(status.into()),
            Ok(Err(e)) => Err(e),
            Err(_timeout) => {
                let _ = child.kill().await;
                Err(InvokeError::Timeout)
            }
        }
    }
}

/// Translates a [`ScriptRunner::run`] result into a rotation outcome, per the README's exit-code
/// table.
pub(crate) fn classify_outcome(
    outcome: Result<ScriptExit, InvokeError>,
    operation: &str,
    timeout_secs: u64,
) -> Result<(), IntegrationError> {
    match outcome {
        Ok(ScriptExit::Code(0)) => Ok(()),
        Ok(exit) => Err(exit_error(exit, operation)),
        Err(InvokeError::Timeout) => Err(timeout_error(operation, timeout_secs)),
        Err(InvokeError::HostNotFound) => Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: RotationFailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind("PowerShellHostNotFound"),
        }),
        Err(InvokeError::StdinWrite) => Err(script_io_error(operation, "ScriptStdinWriteFailed")),
        Err(InvokeError::Wait) => Err(script_io_error(operation, "ScriptWaitFailed")),
        Err(_) => Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: RotationFailureCode::Internal,
            detail: SafeDetail::from_kind("ScriptSpawnError"),
        }),
    }
}

fn script_io_error(operation: &str, kind: &'static str) -> IntegrationError {
    IntegrationError {
        class: ErrorClass::Fatal,
        effect: match operation {
            "rotate" => TargetEffect::Unknown,
            _ => TargetEffect::NotApplied,
        },
        code: RotationFailureCode::Internal,
        detail: SafeDetail::from_kind(kind),
    }
}

fn timeout_error(operation: &str, timeout_secs: u64) -> IntegrationError {
    let effect = match operation {
        "rotate" => TargetEffect::Unknown,
        "verify" => TargetEffect::Applied,
        _ => TargetEffect::NotApplied,
    };
    IntegrationError {
        class: ErrorClass::Fatal,
        effect,
        code: RotationFailureCode::ScriptTimeout,
        detail: SafeDetail::timed_out(timeout_secs),
    }
}

fn exit_error(exit: ScriptExit, operation: &str) -> IntegrationError {
    let (class, effect, detail) = match exit {
        ScriptExit::Code(1) => (
            ErrorClass::Fatal,
            TargetEffect::NotApplied,
            SafeDetail::from_exit_code(1),
        ),
        ScriptExit::Code(2) => (
            ErrorClass::Fatal,
            TargetEffect::Applied,
            SafeDetail::from_exit_code(2),
        ),
        ScriptExit::Code(3) => (
            ErrorClass::Fatal,
            TargetEffect::Unknown,
            SafeDetail::from_exit_code(3),
        ),
        ScriptExit::Code(4) => (
            ErrorClass::Transient,
            TargetEffect::NotApplied,
            SafeDetail::from_exit_code(4),
        ),
        // Unknown exit code or signal termination.
        other => {
            let effect = match operation {
                "rotate" => TargetEffect::Unknown,
                _ => TargetEffect::NotApplied,
            };
            let detail = match other {
                ScriptExit::Code(n) => SafeDetail::from_exit_code(n),
                ScriptExit::Signal(Some(n)) => SafeDetail::from_signal(n),
                ScriptExit::Signal(None) => SafeDetail::from_kind("signal"),
            };
            (ErrorClass::Fatal, effect, detail)
        }
    };
    IntegrationError {
        class,
        effect,
        code: RotationFailureCode::ScriptFailed,
        detail,
    }
}

/// A [`ScriptRunner`] that records what it was asked to run and returns a canned outcome.
#[cfg(test)]
pub(crate) struct RecordingRunner {
    reply: Result<ScriptExit, InvokeError>,
    calls: std::sync::Mutex<Vec<(CommandSpec, Vec<u8>)>>,
}

#[cfg(test)]
impl RecordingRunner {
    pub(crate) fn exiting(code: i32) -> Self {
        Self {
            reply: Ok(ScriptExit::Code(code)),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn failing(err: InvokeError) -> Self {
        Self {
            reply: Err(err),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn only_call(&self) -> (CommandSpec, Vec<u8>) {
        let calls = self.calls.lock().expect("recorder lock");
        assert_eq!(calls.len(), 1, "expected exactly one invocation");
        calls[0].clone()
    }

    pub(crate) fn only_payload(&self) -> serde_json::Value {
        let (_, payload) = self.only_call();
        serde_json::from_slice(&payload).expect("payload must be JSON")
    }
}

#[cfg(test)]
#[async_trait]
impl ScriptRunner for RecordingRunner {
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        _timeout: Duration,
    ) -> Result<ScriptExit, InvokeError> {
        self.calls
            .lock()
            .expect("recorder lock")
            .push((spec, payload.to_vec()));
        self.reply.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::FakeFs;

    fn creds_with_script(path: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT".to_string(), path.to_string());
        creds
    }

    fn detail_of(err: IntegrationError) -> String {
        err.detail.as_str().to_string()
    }

    #[test]
    fn resolve_script_path_requires_the_script_credential() {
        let err =
            resolve_script_path(&ResolvedCredentials::new(), None, &FakeFs::empty()).unwrap_err();
        assert_eq!(detail_of(err), "error kind: MissingScript");
    }

    #[test]
    fn resolve_script_path_rejects_a_path_that_does_not_exist() {
        let err = resolve_script_path(
            &creds_with_script("/opt/missing.sh"),
            None,
            &FakeFs::empty(),
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptNotFound");
    }

    #[test]
    fn resolve_script_path_accepts_a_script_under_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_file("/opt/bwac/rotate.sh");
        let resolved = resolve_script_path(
            &creds_with_script("/opt/bwac/rotate.sh"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/opt/bwac/rotate.sh"));
    }

    #[test]
    fn resolve_script_path_rejects_a_script_outside_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_file("/etc/passwd");
        let err = resolve_script_path(
            &creds_with_script("/etc/passwd"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptOutsideRoot");
    }

    /// Containment is checked after resolution, so an in-root link pointing out is rejected. Real
    /// symlinks are covered in `tests/scripting_integration.rs`.
    #[test]
    fn resolve_script_path_rejects_a_link_escaping_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_link("/opt/bwac/escape.sh", "/bin/sh");
        let err = resolve_script_path(
            &creds_with_script("/opt/bwac/escape.sh"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptOutsideRoot");
    }

    #[test]
    fn resolve_script_path_rejects_an_unresolvable_root() {
        let fs = FakeFs::empty().with_file("/opt/bwac/rotate.sh");
        let err = resolve_script_path(
            &creds_with_script("/opt/bwac/rotate.sh"),
            Some(Path::new("/nonexistent")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptRootInvalid");
    }

    fn creds_with_script_type(value: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT_TYPE".to_string(), value.to_string());
        creds
    }

    #[test]
    fn parse_accepts_known_types_case_insensitively() {
        assert_eq!(ScriptType::parse("direct"), Some(ScriptType::Direct));
        assert_eq!(
            ScriptType::parse("powershell"),
            Some(ScriptType::Powershell)
        );
        assert_eq!(
            ScriptType::parse("PowerShell"),
            Some(ScriptType::Powershell)
        );
        assert_eq!(
            ScriptType::parse("  POWERSHELL  "),
            Some(ScriptType::Powershell)
        );
    }

    #[test]
    fn parse_rejects_unknown_type() {
        assert_eq!(ScriptType::parse("bash"), None);
        assert_eq!(ScriptType::parse("pwsh"), None);
        assert_eq!(ScriptType::parse(""), None);
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for t in [ScriptType::Direct, ScriptType::Powershell] {
            assert_eq!(ScriptType::parse(t.as_str()), Some(t));
        }
    }

    #[test]
    fn detect_selects_powershell_for_ps1() {
        let t = ScriptType::detect(Path::new("/opt/bwac/rotate.ps1"), None);
        assert_eq!(t, ScriptType::Powershell);
    }

    #[test]
    fn detect_is_case_insensitive_on_the_extension() {
        // Windows paths routinely differ in case.
        for name in ["rotate.PS1", "rotate.Ps1", "rotate.pS1"] {
            assert_eq!(
                ScriptType::detect(Path::new(name), None),
                ScriptType::Powershell,
                "{name} should select PowerShell"
            );
        }
    }

    #[test]
    fn detect_selects_direct_for_everything_else() {
        for name in ["rotate.sh", "rotate.exe", "rotate", "rotate.ps1.bak"] {
            assert_eq!(
                ScriptType::detect(Path::new(name), None),
                ScriptType::Direct,
                "{name} should execute directly"
            );
        }
    }

    #[test]
    fn explicit_type_overrides_the_extension_both_ways() {
        assert_eq!(
            ScriptType::detect(Path::new("rotate.ps1"), Some(ScriptType::Direct)),
            ScriptType::Direct
        );
        assert_eq!(
            ScriptType::detect(Path::new("rotate"), Some(ScriptType::Powershell)),
            ScriptType::Powershell
        );
    }

    #[test]
    fn resolve_script_type_falls_back_to_the_extension() {
        let creds = ResolvedCredentials::new();
        assert_eq!(
            resolve_script_type(&creds, Path::new("/opt/rotate.ps1")).unwrap(),
            ScriptType::Powershell
        );
        assert_eq!(
            resolve_script_type(&creds, Path::new("/opt/rotate.sh")).unwrap(),
            ScriptType::Direct
        );
    }

    #[test]
    fn resolve_script_type_lets_the_credential_override_the_extension() {
        assert_eq!(
            resolve_script_type(
                &creds_with_script_type("direct"),
                Path::new("/opt/rotate.ps1")
            )
            .unwrap(),
            ScriptType::Direct
        );
        assert_eq!(
            resolve_script_type(
                &creds_with_script_type("powershell"),
                Path::new("/opt/rotate")
            )
            .unwrap(),
            ScriptType::Powershell
        );
    }

    #[test]
    fn resolve_script_type_rejects_an_unknown_value() {
        let err = resolve_script_type(
            &creds_with_script_type("pwsh"),
            Path::new("/opt/rotate.ps1"),
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: UnknownScriptType");
    }

    #[test]
    fn classify_outcome_maps_the_exit_code_table() {
        let cases = [
            (1, ErrorClass::Fatal, TargetEffect::NotApplied),
            (2, ErrorClass::Fatal, TargetEffect::Applied),
            (3, ErrorClass::Fatal, TargetEffect::Unknown),
            (4, ErrorClass::Transient, TargetEffect::NotApplied),
        ];
        for (code, class, effect) in cases {
            let err = classify_outcome(Ok(ScriptExit::Code(code)), "rotate", 60).unwrap_err();
            assert_eq!(err.class, class, "exit {code}");
            assert_eq!(err.effect, effect, "exit {code}");
            assert_eq!(err.code, RotationFailureCode::ScriptFailed, "exit {code}");
        }
        classify_outcome(Ok(ScriptExit::Code(0)), "rotate", 60).unwrap();
    }

    #[test]
    fn classify_outcome_reports_the_signal_number() {
        let err = classify_outcome(Ok(ScriptExit::Signal(Some(9))), "rotate", 60).unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.code, RotationFailureCode::ScriptFailed);
        assert_eq!(err.detail.as_str(), "signal 9");
    }

    #[test]
    fn classify_outcome_names_a_signal_without_a_number() {
        let err = classify_outcome(Ok(ScriptExit::Signal(None)), "rotate", 60).unwrap_err();
        assert_eq!(err.detail.as_str(), "error kind: signal");
    }

    #[test]
    fn classify_outcome_signal_leaves_a_non_rotate_target_alone() {
        let err = classify_outcome(Ok(ScriptExit::Signal(Some(9))), "verify", 60).unwrap_err();
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[test]
    fn classify_outcome_timeout_effect_depends_on_the_operation() {
        for (operation, effect) in [
            ("rotate", TargetEffect::Unknown),
            ("verify", TargetEffect::Applied),
            ("terminate", TargetEffect::NotApplied),
        ] {
            let err = classify_outcome(Err(InvokeError::Timeout), operation, 60).unwrap_err();
            assert_eq!(err.code, RotationFailureCode::ScriptTimeout, "{operation}");
            assert_eq!(err.effect, effect, "{operation}");
        }
    }

    #[test]
    fn classify_outcome_does_not_claim_rotate_left_the_target_alone() {
        for err in [InvokeError::StdinWrite, InvokeError::Wait] {
            let rotate = classify_outcome(Err(err.clone()), "rotate", 60).unwrap_err();
            assert_eq!(rotate.effect, TargetEffect::Unknown, "{err:?}");

            for operation in ["verify", "terminate"] {
                let other = classify_outcome(Err(err.clone()), operation, 60).unwrap_err();
                assert_eq!(
                    other.effect,
                    TargetEffect::NotApplied,
                    "{err:?}/{operation}"
                );
            }
        }
    }

    #[test]
    fn classify_outcome_names_the_failing_stage() {
        let write = classify_outcome(Err(InvokeError::StdinWrite), "rotate", 60).unwrap_err();
        assert_eq!(write.detail.as_str(), "error kind: ScriptStdinWriteFailed");

        let wait = classify_outcome(Err(InvokeError::Wait), "rotate", 60).unwrap_err();
        assert_eq!(wait.detail.as_str(), "error kind: ScriptWaitFailed");
    }

    #[test]
    fn classify_outcome_separates_a_missing_host_from_a_spawn_failure() {
        let missing = classify_outcome(Err(InvokeError::HostNotFound), "rotate", 60).unwrap_err();
        assert_eq!(missing.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(
            missing.detail.as_str(),
            "error kind: PowerShellHostNotFound"
        );

        let spawn = classify_outcome(Err(InvokeError::Spawn), "rotate", 60).unwrap_err();
        assert_eq!(spawn.code, RotationFailureCode::Internal);
        assert_eq!(spawn.detail.as_str(), "error kind: ScriptSpawnError");
    }
}
