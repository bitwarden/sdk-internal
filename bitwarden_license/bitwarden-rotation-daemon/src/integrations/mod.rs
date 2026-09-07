//! Integration drivers for external credential targets.
//!
//! Defines the [`Integration`] trait every target-system driver implements, plus its shared
//! types: [`TargetEffect`], [`IntegrationError`], [`RotateContext`], and [`IntegrationRegistry`].
//! [`TargetKind`] lives in [`crate::api::models`], re-exported here for the resolver.

pub(crate) mod custom_script;
pub(crate) mod entra;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Re-export [`TargetKind`] so resolver and integration modules can import from
/// a single location.
pub(crate) use crate::api::models::TargetKind;
use crate::{
    error::{ErrorClass, FailureCode, SafeDetail},
    resolver::ResolvedCredentials,
};

/// Whether the target system's credential was (or might have been) changed
/// before an error occurred.
///
/// Used to populate [`IntegrationError`] so the executor can pick the correct
/// [`crate::error::SyncState`] for the failure report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetEffect {
    /// The credential rotation was not applied; target and vault are still in sync.
    NotApplied,
    /// The credential was successfully rotated in the target system.
    Applied,
    /// It is not known whether the rotation was applied (e.g. timeout after send).
    Unknown,
}

/// An error returned by any [`Integration`] operation.
///
/// Carries what the executor needs for a failure report: `class` (retry or not), `effect`
/// (target sync state), `code` (failure reason), and `detail` (a safe, secret-free string).
#[derive(Debug)]
pub(crate) struct IntegrationError {
    /// Transient (retriable) or fatal (abort immediately).
    pub(crate) class: ErrorClass,
    /// Whether the target's credential was changed before this error.
    pub(crate) effect: TargetEffect,
    /// Failure reason code to include in the server failure report.
    pub(crate) code: FailureCode,
    /// Safe, bounded detail string (contains only status codes, exit codes,
    /// variable names, and static strings, never secret values).
    pub(crate) detail: SafeDetail,
}

impl std::fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?} ({:?}): {}",
            self.class, self.effect, self.code, self.detail
        )
    }
}

impl std::error::Error for IntegrationError {}

/// The self-contained work snapshot passed to every [`Integration`] operation.
///
/// Constructed by the executor from the claim response and resolved credentials.
/// Secrets inside `new_password` and `creds` are zeroized on drop.
pub(crate) struct RotateContext {
    /// The target system identifier from the claim.
    pub(crate) target_system_id: Uuid,
    /// The opaque account identity string (e.g. a user principal name or object id).
    pub(crate) account_identity: String,
    /// The newly generated password to rotate to; `Zeroizing` wipes it from
    /// memory on drop.
    pub(crate) new_password: Zeroizing<String>,
    /// Resolved credentials for authenticating to the target system.
    pub(crate) creds: ResolvedCredentials,
    /// Wall-clock time at which password generation completed (step 2 of
    /// `ExecuteRotation`).  Used by verify implementations to determine whether
    /// `lastPasswordChangeDateTime` is fresh enough.
    pub(crate) rotation_started_at: DateTime<Utc>,
}

// Suppress the default Debug which would print new_password.
impl std::fmt::Debug for RotateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateContext")
            .field("target_system_id", &self.target_system_id)
            .field("account_identity", &self.account_identity)
            .field("new_password", &"[REDACTED]")
            .field("rotation_started_at", &self.rotation_started_at)
            .finish()
    }
}

/// Trait implemented by each target-system driver (Entra, CustomScript, …).
///
/// All methods take a shared [`RotateContext`] and return `()` or an [`IntegrationError`]
/// (`class`, `effect`, `code`, `detail`), mapped into a failure report by the executor. No
/// `#[async_trait(?Send)]` per `CLAUDE.md`: integrations are native-only.
#[async_trait]
pub(crate) trait Integration: Send + Sync {
    /// Rotate the credential for `ctx.account_identity` to `ctx.new_password`
    /// in the target system.
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Verify that the rotation applied in the target system.
    ///
    /// For custom scripts this is a mandatory step (no v0 opt-out); the
    /// script's exit code determines success or failure.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Terminate active sessions for `ctx.account_identity` in the target system.
    /// Gated by the claim's `terminate_sessions` flag.
    ///
    /// A failure here must not fail the overall rotation: the executor uses a
    /// `TerminationNeverFailsRotation` discipline (step 6).
    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;
}

/// Maps a [`TargetKind`] to the concrete [`Integration`] driver for that kind.
///
/// Unregistered kinds (e.g. `Mssql`, which is parsed from the wire but has no
/// driver in this build) return `None`; the executor then reports
/// `unsupported_kind`.
pub(crate) struct IntegrationRegistry {
    map: HashMap<TargetKind, Arc<dyn Integration>>,
}

impl IntegrationRegistry {
    /// Creates an empty registry.
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Registers a driver for the given kind.
    pub(crate) fn register(&mut self, kind: TargetKind, integration: Arc<dyn Integration>) {
        self.map.insert(kind, integration);
    }

    /// The driver for the given kind, or `None` absent a registration.
    pub(crate) fn get(&self, kind: TargetKind) -> Option<Arc<dyn Integration>> {
        self.map.get(&kind).cloned()
    }
}

impl Default for IntegrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysOk;

    #[async_trait]
    impl Integration for AlwaysOk {
        async fn rotate(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            Ok(())
        }
        async fn verify(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            Ok(())
        }
        async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
            Ok(())
        }
    }

    #[test]
    fn registry_get_registered_kind() {
        let mut reg = IntegrationRegistry::new();
        reg.register(TargetKind::CustomScript, Arc::new(AlwaysOk));
        assert!(reg.get(TargetKind::CustomScript).is_some());
    }

    #[test]
    fn registry_get_unregistered_kind_returns_none() {
        let reg = IntegrationRegistry::new();
        assert!(reg.get(TargetKind::Mssql).is_none());
        assert!(reg.get(TargetKind::Entra).is_none());
    }

    #[test]
    fn target_effect_variants_exist() {
        let _a = TargetEffect::NotApplied;
        let _b = TargetEffect::Applied;
        let _c = TargetEffect::Unknown;
    }

    #[test]
    fn integration_error_display() {
        let e = IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::ScriptFailed,
            detail: SafeDetail::from_exit_code(1),
        };
        let s = e.to_string();
        assert!(s.contains("ScriptFailed"));
        assert!(s.contains("exit code 1"));
    }

    #[test]
    fn rotate_context_debug_redacts_password() {
        let ctx = RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: Zeroizing::new("super-secret-pw".to_string()),
            creds: ResolvedCredentials::new(),
            rotation_started_at: Utc::now(),
        };
        let debug = format!("{ctx:?}");
        assert!(
            !debug.contains("super-secret-pw"),
            "password leaked: {debug}"
        );
        assert!(debug.contains("REDACTED"));
    }
}
