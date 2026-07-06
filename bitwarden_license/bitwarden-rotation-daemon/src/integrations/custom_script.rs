//! Custom-script integration for arbitrary credential rotation targets.
//!
//! [`CustomScriptIntegration`] invokes an operator-supplied executable for each
//! rotation operation (`rotate`, `verify`, `terminate`).  The executable path
//! comes from the resolver's `SCRIPT` credential.
//!
//! # Security contract (documented in README)
//!
//! - Secrets are delivered **only** via stdin as a single JSON document — never
//!   via argv or process environment variables.  (`/proc/<pid>/cmdline` and
//!   `ps` can expose argv; env can be read by child processes.)
//! - `stdout` and `stderr` are always redirected to `/dev/null` (i.e.
//!   `Stdio::null()`).  Script output can echo credentials; piping it unread
//!   would also deadlock a chatty script.
//! - The `SCRIPT` credential is excluded from the `credentials` map forwarded
//!   to the script (the script already knows its own path).
//! - If `script_root` is set, the canonicalized script path must be under the
//!   canonicalized root, preventing `../` traversal and symlink escapes.
//!
//! # Payload shape (stdin)
//!
//! ```json
//! {
//!   "operation": "rotate",
//!   "targetSystemId": "…uuid…",
//!   "accountIdentity": "…",
//!   "newPassword": "…",
//!   "credentials": { "EXTRA_KEY": "value", … }
//! }
//! ```
//!
//! For the `terminate` operation `newPassword` is **omitted** (the script
//! must not be able to receive or echo back a password it does not need).
//!
//! # Exit codes
//!
//! | Code    | Meaning                                                             |
//! |---------|---------------------------------------------------------------------|
//! | 0       | Success                                                             |
//! | 1       | Fatal failure — target unchanged (rotate) / not applied             |
//! | 2       | Fatal failure — target was updated (rotation applied, verify failed) |
//! | 3       | Fatal failure — unknown sync state (timeout after send, etc.)       |
//! | 4       | Transient failure — retry may succeed                               |
//! | other   | Fatal, unknown sync state (treated as unexpected / signal)          |
//! | timeout | Killed by daemon; rotate → unknown, verify → applied, terminate → not_applied |
//!
//! # RotationByAdministrativeReset
//!
//! The payload never contains the **current** password.  Scripts **must**
//! perform an administrative (force) reset, not a change-password operation.
//! A change-password script is incompatible with retry convergence: if the
//! first attempt succeeds (target updated) but the report fails, the daemon
//! retries with a new `newPassword`; a change-password script would then fail
//! because the "current" password it was given was already changed.
//!
//! # verify — no v0 opt-out
//!
//! `verify` is mandatory.  A script that cannot round-trip-authenticate must
//! still implement `verify` with its best available applied-check (e.g.
//! querying the target system's last-password-change timestamp).

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use serde::Serialize;
use tokio::time;

use super::{Integration, IntegrationError, RotateContext, TargetEffect};
use crate::error::{ErrorClass, FailureCode, SafeDetail};

// ---------------------------------------------------------------------------
// CustomScriptIntegration
// ---------------------------------------------------------------------------

/// Integration driver that delegates all operations to an operator-supplied
/// executable.
pub(crate) struct CustomScriptIntegration {
    /// If set, scripts must resolve to a path under this root (prevents
    /// `../` traversal and symlink escapes).
    pub(crate) script_root: Option<PathBuf>,
    /// Maximum time to wait for the script to complete.
    pub(crate) timeout: Duration,
}

impl CustomScriptIntegration {
    /// Creates a new integration with the given optional root restriction and
    /// timeout.
    pub(crate) fn new(script_root: Option<PathBuf>, timeout: Duration) -> Self {
        Self {
            script_root,
            timeout,
        }
    }
}

// ---------------------------------------------------------------------------
// Stdin payload
// ---------------------------------------------------------------------------

/// The JSON document written to the script's stdin.
///
/// `newPassword` is `None` for the `terminate` operation so it is serialised as
/// absent (with `skip_serializing_if`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptPayload<'a> {
    operation: &'a str,
    target_system_id: &'a uuid::Uuid,
    account_identity: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_password: Option<&'a str>,
    /// Credential map forwarded to the script — SCRIPT key excluded.
    credentials: std::collections::HashMap<&'a str, &'a str>,
}

// ---------------------------------------------------------------------------
// Path resolution + script-root guard
// ---------------------------------------------------------------------------

/// Resolves the script path from the credentials map and optionally checks that
/// the canonicalized path is under the canonicalized root.
fn resolve_script_path(
    creds: &super::super::resolver::ResolvedCredentials,
    script_root: Option<&Path>,
) -> Result<PathBuf, IntegrationError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    let script_val = creds.get("SCRIPT").ok_or_else(|| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: FailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind("MissingScript"),
    })?;

    let script_str = script_val.expose();
    let raw_path = PathBuf::from(script_str.as_ref() as &str);

    let canonical = raw_path.canonicalize().map_err(|_| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: FailureCode::CredentialsUnresolved,
        detail: SafeDetail::from_kind("ScriptNotFound"),
    })?;

    if let Some(root) = script_root {
        let canonical_root = root.canonicalize().map_err(|_| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind("ScriptRootInvalid"),
        })?;

        if !canonical.starts_with(&canonical_root) {
            return Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::NotApplied,
                code: FailureCode::CredentialsUnresolved,
                detail: SafeDetail::from_kind("ScriptOutsideRoot"),
            });
        }
    }

    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Invocation
// ---------------------------------------------------------------------------

/// Runs the script for the given operation and returns the exit code.
///
/// `new_password` is `None` for the `terminate` operation.
async fn invoke(
    script_path: &Path,
    operation: &str,
    ctx: &RotateContext,
    new_password: Option<&str>,
    timeout: Duration,
) -> Result<Option<i32>, InvokeError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;
    use tokio::io::AsyncWriteExt as _;
    use tokio::process::Command;

    // Build the credentials map — exclude SCRIPT.
    let mut credentials: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (k, v) in ctx.creds.iter() {
        if k != "SCRIPT" {
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

    let payload_json = serde_json::to_vec(&payload).map_err(|_| InvokeError::Serialize)?;

    // Spawn the process:
    //   - argv: [script_path, operation]  — no secrets in argv
    //   - stdin: piped (we write the JSON, then drop)
    //   - stdout: null (script output may echo credentials; piped+unread deadlocks)
    //   - stderr: null (same reason)
    //   - kill_on_drop: true (guard against timeout leaving a zombie)
    let mut child = Command::new(script_path)
        .arg(operation)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| InvokeError::Spawn)?;

    // Write the payload then drop stdin so the script can read to EOF.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&payload_json)
            .await
            .map_err(|_| InvokeError::StdinWrite)?;
        // stdin is dropped here → the script's read reaches EOF
    }

    // Apply timeout.
    match time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => Ok(status.code()),
        Ok(Err(_)) => Err(InvokeError::Wait),
        Err(_timeout) => {
            // Kill the child (kill_on_drop also does this when the child is
            // dropped, but we want to be explicit before returning).
            let _ = child.kill().await;
            Err(InvokeError::Timeout)
        }
    }
}

/// Internal errors from script invocation (not exposed outside this module).
#[derive(Debug)]
enum InvokeError {
    Serialize,
    Spawn,
    StdinWrite,
    Wait,
    Timeout,
}

/// Maps an [`InvokeError::Timeout`] to an [`IntegrationError`] using the
/// operation-specific timeout semantics.
fn timeout_error(operation: &str, timeout_secs: u64) -> IntegrationError {
    // Per spec:
    //   rotate timeout  → Unknown  (we don't know if the target was updated)
    //   verify timeout  → Applied  (conservative: assume the password was changed)
    //   terminate timeout → NotApplied (terminate never changes the credential)
    let effect = match operation {
        "rotate" => TargetEffect::Unknown,
        "verify" => TargetEffect::Applied,
        _ => TargetEffect::NotApplied,
    };
    IntegrationError {
        class: ErrorClass::Fatal,
        effect,
        code: FailureCode::ScriptTimeout,
        detail: SafeDetail::timed_out(timeout_secs),
    }
}

/// Maps an exit code (or None = signal) to an [`IntegrationError`] using the
/// documented exit-code table.
///
/// For `other/signal` the sync state depends on the operation:
///   rotate → Unknown, verify → NotApplied, terminate → NotApplied
fn exit_code_error(code: Option<i32>, operation: &str) -> IntegrationError {
    match code {
        Some(0) => unreachable!("exit 0 is success, not an error"),
        Some(1) => IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::ScriptFailed,
            detail: SafeDetail::from_exit_code(1),
        },
        Some(2) => IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::Applied,
            code: FailureCode::ScriptFailed,
            detail: SafeDetail::from_exit_code(2),
        },
        Some(3) => IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::Unknown,
            code: FailureCode::ScriptFailed,
            detail: SafeDetail::from_exit_code(3),
        },
        Some(4) => IntegrationError {
            class: ErrorClass::Transient,
            effect: TargetEffect::NotApplied,
            code: FailureCode::ScriptFailed,
            detail: SafeDetail::from_exit_code(4),
        },
        other => {
            // Unknown exit code or signal termination.
            let effect = match operation {
                "rotate" => TargetEffect::Unknown,
                _ => TargetEffect::NotApplied,
            };
            IntegrationError {
                class: ErrorClass::Fatal,
                effect,
                code: FailureCode::ScriptFailed,
                detail: match other {
                    Some(n) => SafeDetail::from_exit_code(n),
                    None => SafeDetail::from_kind("signal"),
                },
            }
        }
    }
}

/// Runs one script operation and translates the outcome to `Result<(), IntegrationError>`.
async fn run_operation(
    script_path: &Path,
    operation: &str,
    ctx: &RotateContext,
    new_password: Option<&str>,
    timeout: Duration,
) -> Result<(), IntegrationError> {
    let timeout_secs = timeout.as_secs();

    match invoke(script_path, operation, ctx, new_password, timeout).await {
        Ok(Some(0)) => Ok(()),
        Ok(code) => Err(exit_code_error(code, operation)),
        Err(InvokeError::Timeout) => Err(timeout_error(operation, timeout_secs)),
        Err(_) => Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::Internal,
            detail: SafeDetail::from_kind("ScriptSpawnError"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Integration impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Integration for CustomScriptIntegration {
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(&ctx.creds, self.script_root.as_deref())?;
        let pw = ctx.new_password.as_str();
        run_operation(&script, "rotate", ctx, Some(pw), self.timeout).await
    }

    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(&ctx.creds, self.script_root.as_deref())?;
        let pw = ctx.new_password.as_str();
        run_operation(&script, "verify", ctx, Some(pw), self.timeout).await
    }

    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let script = resolve_script_path(&ctx.creds, self.script_root.as_deref())?;
        // newPassword is OMITTED for terminate (script has no need for it; withholding
        // it prevents accidental echo in any script-side logging).
        run_operation(&script, "terminate", ctx, None, self.timeout).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{io::Read as _, path::PathBuf, time::Duration};

    use chrono::Utc;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        error::{ErrorClass, FailureCode},
        integrations::{RotateContext, TargetEffect},
        resolver::ResolvedCredentials,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn fixture_path(name: &str) -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests");
        p.push("fixtures");
        p.push(name);
        p
    }

    fn make_ctx_with_creds(creds: ResolvedCredentials) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: Zeroizing::new("super-secret-pw-SENTINEL".to_string()),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn integration(root: Option<PathBuf>, timeout_secs: u64) -> CustomScriptIntegration {
        CustomScriptIntegration::new(root, Duration::from_secs(timeout_secs))
    }

    // -----------------------------------------------------------------------
    // Script-root escape rejection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn script_root_dotdot_rejected() {
        let root = fixture_path(".");
        let mut creds = ResolvedCredentials::new();
        // Construct a path that goes up one level from the root.
        let escape = root.join("../../../etc/passwd");
        creds.insert("SCRIPT".to_string(), escape.to_string_lossy().to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(Some(root), 5);
        let err = integ.rotate(&ctx).await.unwrap_err();
        // Either ScriptNotFound (file doesn't exist) or CredentialsUnresolved
        // (root escape detected after canonicalize).
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.class, ErrorClass::Fatal);
    }

    #[tokio::test]
    async fn script_root_symlink_outside_root_rejected() {
        // Create a temp dir as root and a symlink inside it pointing outside.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let link = root.join("evil_link.sh");
        // Point the symlink at a real existing file that is outside the root.
        // On macOS and Linux, /bin/sh always exists.
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();

        // Now use a script_root that DOES NOT include /bin, so the symlink
        // canonicalizes to /bin/sh which is outside tmp root.
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT".to_string(), link.to_string_lossy().to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(Some(root), 5);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.class, ErrorClass::Fatal);
    }

    // -----------------------------------------------------------------------
    // Stdin payload correctness
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stdin_payload_contains_correct_fields() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("payload.json");

        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("copy_stdin.sh").to_string_lossy().to_string(),
        );
        creds.insert("OUT_PATH".to_string(), out.to_string_lossy().to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);

        integ.rotate(&ctx).await.unwrap();

        let mut buf = String::new();
        std::fs::File::open(&out)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&buf).unwrap();
        assert_eq!(v["operation"], "rotate");
        assert_eq!(v["targetSystemId"], Uuid::nil().to_string().as_str());
        assert_eq!(v["accountIdentity"], "user@example.com");
        assert!(
            v.get("newPassword").is_some(),
            "newPassword must be present for rotate"
        );
        // SCRIPT must be excluded from the forwarded credentials map.
        assert!(
            v["credentials"].get("SCRIPT").is_none(),
            "SCRIPT must not appear in forwarded credentials"
        );
        // OUT_PATH should be forwarded (it's not SCRIPT).
        assert!(v["credentials"].get("OUT_PATH").is_some());
    }

    #[tokio::test]
    async fn stdin_payload_omits_new_password_for_terminate() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("payload_terminate.json");

        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("copy_stdin.sh").to_string_lossy().to_string(),
        );
        creds.insert("OUT_PATH".to_string(), out.to_string_lossy().to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);

        integ.terminate_sessions(&ctx).await.unwrap();

        let mut buf = String::new();
        std::fs::File::open(&out)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&buf).unwrap();
        assert_eq!(v["operation"], "terminate");
        assert!(
            v.get("newPassword").is_none(),
            "newPassword must be absent for terminate: {v}"
        );
    }

    // -----------------------------------------------------------------------
    // Exit code mapping
    // -----------------------------------------------------------------------

    async fn run_exit_code(code: i32) -> Result<(), IntegrationError> {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("exit_code.sh").to_string_lossy().to_string(),
        );
        creds.insert("EXIT_CODE".to_string(), code.to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);
        integ.rotate(&ctx).await
    }

    #[tokio::test]
    async fn exit_0_is_success() {
        run_exit_code(0).await.unwrap();
    }

    #[tokio::test]
    async fn exit_1_fatal_not_applied() {
        let err = run_exit_code(1).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::ScriptFailed);
    }

    #[tokio::test]
    async fn exit_2_fatal_applied() {
        let err = run_exit_code(2).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Applied);
        assert_eq!(err.code, FailureCode::ScriptFailed);
    }

    #[tokio::test]
    async fn exit_3_fatal_unknown() {
        let err = run_exit_code(3).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.code, FailureCode::ScriptFailed);
    }

    #[tokio::test]
    async fn exit_4_transient_not_applied() {
        let err = run_exit_code(4).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Transient);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::ScriptFailed);
    }

    #[tokio::test]
    async fn exit_99_other_fatal_unknown_for_rotate() {
        let err = run_exit_code(99).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.code, FailureCode::ScriptFailed);
    }

    #[tokio::test]
    async fn exit_99_other_fatal_not_applied_for_verify() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("exit_code.sh").to_string_lossy().to_string(),
        );
        creds.insert("EXIT_CODE".to_string(), "99".to_string());
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);
        let err = integ.verify(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn timeout_kills_script_rotate_gives_unknown() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("sleep_forever.sh")
                .to_string_lossy()
                .to_string(),
        );
        let ctx = make_ctx_with_creds(creds);
        // Very short timeout so the test doesn't take long.
        let integ = integration(None, 1);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.code, FailureCode::ScriptTimeout);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.class, ErrorClass::Fatal);
    }

    #[tokio::test]
    async fn timeout_kills_script_verify_gives_applied() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("sleep_forever.sh")
                .to_string_lossy()
                .to_string(),
        );
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 1);
        let err = integ.verify(&ctx).await.unwrap_err();
        assert_eq!(err.code, FailureCode::ScriptTimeout);
        assert_eq!(err.effect, TargetEffect::Applied);
    }

    #[tokio::test]
    async fn timeout_kills_script_terminate_gives_not_applied() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("sleep_forever.sh")
                .to_string_lossy()
                .to_string(),
        );
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 1);
        let err = integ.terminate_sessions(&ctx).await.unwrap_err();
        assert_eq!(err.code, FailureCode::ScriptTimeout);
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    // -----------------------------------------------------------------------
    // No-leak (argv + env)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_password_in_argv_or_env() {
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("no_leak.sh").to_string_lossy().to_string(),
        );
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);
        // no_leak.sh exits 0 only if the sentinel does NOT appear in argv or env.
        integ.rotate(&ctx).await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Only operation in argv
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn only_operation_in_argv() {
        // no_leak.sh also asserts exactly 1 argument.
        let mut creds = ResolvedCredentials::new();
        creds.insert(
            "SCRIPT".to_string(),
            fixture_path("no_leak.sh").to_string_lossy().to_string(),
        );
        let ctx = make_ctx_with_creds(creds);
        let integ = integration(None, 10);
        integ.verify(&ctx).await.unwrap();
        integ.terminate_sessions(&ctx).await.unwrap();
    }
}
