//! Integration drivers for external credential targets.
//!
//! This module defines the [`Integration`] trait that all target-system
//! drivers implement, plus the shared types they depend on:
//!
//! - [`TargetEffect`]: whether the target's credential was changed before an error.
//! - [`IntegrationError`]: the error type returned by all integration operations.
//! - [`RotateContext`]: the work snapshot passed into every integration operation.
//! - [`IntegrationRegistry`]: maps a [`TargetKind`] to the right driver.
//!
//! # TargetKind
//!
//! [`TargetKind`] is defined in [`crate::api::models`] and re-exported here for
//! use by the resolver and integration implementations.  The local mirror that
//! was written while `api/models.rs` was still a stub has been removed now that
//! the parallel agent has landed the canonical definition.

pub(crate) mod custom_script;
pub(crate) mod entra;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::{ErrorClass, FailureCode, SafeDetail},
    resolver::ResolvedCredentials,
};

/// Re-export [`TargetKind`] so resolver and integration modules can import from
/// a single location.
pub(crate) use crate::api::models::TargetKind;

// ---------------------------------------------------------------------------
// TargetEffect
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// IntegrationError
// ---------------------------------------------------------------------------

/// An error returned by any [`Integration`] operation.
///
/// Carries all the information the executor needs to build a failure report:
/// - `class`: whether retry would help ([`ErrorClass::Transient`]) or not
///   ([`ErrorClass::Fatal`]).
/// - `effect`: the synchronisation state of the target at the time of failure.
/// - `code`: the failure reason code reported to the server.
/// - `detail`: a bounded, zero-knowledge detail string (never contains secrets).
#[derive(Debug)]
pub(crate) struct IntegrationError {
    /// Transient (retriable) or fatal (abort immediately).
    pub(crate) class: ErrorClass,
    /// Whether the target's credential was changed before this error.
    pub(crate) effect: TargetEffect,
    /// Failure reason code to include in the server failure report.
    pub(crate) code: FailureCode,
    /// Safe, bounded detail string (contains only status codes, exit codes,
    /// variable names, and static strings — never secret values).
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

// ---------------------------------------------------------------------------
// RotateContext
// ---------------------------------------------------------------------------

/// The self-contained work snapshot passed to every [`Integration`] operation.
///
/// Constructed by the executor from the claim response and resolved credentials.
/// Secrets inside `new_password` and `creds` are zeroized on drop.
pub(crate) struct RotateContext {
    /// The target system identifier from the claim.
    pub(crate) target_system_id: Uuid,
    /// The opaque account identity string (e.g. a user principal name or object id).
    pub(crate) account_identity: String,
    /// The newly generated password to rotate to.  `Zeroizing` ensures it is
    /// wiped from memory when the context is dropped.
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

// ---------------------------------------------------------------------------
// Integration trait
// ---------------------------------------------------------------------------

/// Trait implemented by each target-system driver (Entra, CustomScript, …).
///
/// All methods receive a shared [`RotateContext`] and return `()` on success or
/// an [`IntegrationError`] (carrying `class`, `effect`, `code`, `detail`) on
/// failure.  The executor maps the error into a failure report.
///
/// # Send + Sync requirement
///
/// Per the repository rule (`CLAUDE.md`): **no `#[async_trait(?Send)]`**.  All
/// integrations are native-only (no WASM context), so plain `async_trait`
/// (which requires `Send`) is correct.
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

    /// Terminate active sessions for `ctx.account_identity` in the target
    /// system.  Called only when the claim's `terminate_sessions` flag is set.
    ///
    /// A failure here must **not** fail the overall rotation — the executor
    /// uses a `TerminationNeverFailsRotation` discipline (step 6).
    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;
}

// ---------------------------------------------------------------------------
// IntegrationRegistry
// ---------------------------------------------------------------------------

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

    /// Returns the driver for the given kind, or `None` if none is registered.
    pub(crate) fn get(&self, kind: TargetKind) -> Option<Arc<dyn Integration>> {
        self.map.get(&kind).cloned()
    }
}

impl Default for IntegrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
