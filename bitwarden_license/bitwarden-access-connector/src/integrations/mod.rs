//! Integration drivers for external credential targets.

pub(crate) mod entra;
pub(crate) mod scripting;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) use crate::api::models::TargetKind;
use crate::{
    error::{ErrorClass, FailureCode, SafeDetail},
    resolver::ResolvedCredentials,
};

/// Whether the target credential was (or might have been) changed before an error, so the
/// executor can report the right [`crate::error::SyncState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetEffect {
    /// The credential rotation was not applied; target and vault are still in sync.
    NotApplied,
    /// The credential was successfully rotated in the target system.
    Applied,
    /// It is not known whether the rotation was applied (e.g. timeout after send).
    Unknown,
}

/// An error returned by any [`Integration`] operation, carrying what the failure report needs.
#[derive(Debug)]
pub(crate) struct IntegrationError {
    pub(crate) class: ErrorClass,
    pub(crate) effect: TargetEffect,
    pub(crate) code: FailureCode,
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

/// Input to every [`Integration`] operation, built from the claim and the resolved credentials.
/// `new_password` and `creds` are zeroized on drop.
pub(crate) struct RotateContext {
    pub(crate) target_system_id: Uuid,
    /// The opaque account identity string (e.g. a user principal name or object id).
    pub(crate) account_identity: String,
    pub(crate) new_password: Zeroizing<String>,
    pub(crate) creds: ResolvedCredentials,
    /// Wall-clock time after password generation (step 2); verify checks
    /// `lastPasswordChangeDateTime` against it.
    pub(crate) rotation_started_at: DateTime<Utc>,
}

// Hand-written to keep new_password and creds out of the output.
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

/// Trait implemented by each target-system driver, such as Entra or CustomScript.
#[async_trait]
pub(crate) trait Integration: Send + Sync {
    /// Rotate the credential for `ctx.account_identity` to `ctx.new_password`
    /// in the target system.
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Verify that the rotation applied in the target system.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Terminate active sessions for `ctx.account_identity` when the claim's `terminate_sessions`
    /// flag is set. A failure here never fails the rotation.
    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;
}

/// Maps a [`TargetKind`] to its [`Integration`] driver. Unregistered kinds such as `Mssql` return
/// `None`, which the executor reports as `unsupported_kind`.
pub(crate) struct IntegrationRegistry {
    map: HashMap<TargetKind, Arc<dyn Integration>>,
}

impl IntegrationRegistry {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub(crate) fn register(&mut self, kind: TargetKind, integration: Arc<dyn Integration>) {
        self.map.insert(kind, integration);
    }

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
