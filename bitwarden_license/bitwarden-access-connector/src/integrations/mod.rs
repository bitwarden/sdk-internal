//! Drivers that apply a rotation to the external system holding the credential.
//!
//! Each target system kind has one [`Integration`], registered against its
//! [`SealedTargetSystemKind`] in an [`IntegrationRegistry`]. For a claimed rotation the executor
//! looks up the driver for the target's kind and calls it in order:
//!
//! 1. [`rotate`](Integration::rotate) sets the account's password to the newly generated one.
//! 2. [`verify`](Integration::verify) confirms the target accepted it, after a successful rotate.
//! 3. [`terminate_sessions`](Integration::terminate_sessions) ends the account's active sessions,
//!    only when the claim asks for it. Its failure never fails the rotation.
//!
//! All three receive the same [`RotateContext`]: the target, the account identity, the new
//! password and the target's [`ResolvedCredentials`].
//!
//! Drivers rotate by administrative reset. The current password is never available to them, so a
//! retry after a partial failure converges on the newest password instead of failing because the
//! "old" one has already changed.
//!
//! # Failures
//!
//! An operation fails with an [`IntegrationError`], which carries everything the failure report
//! needs: whether to [`Retry`], the [`RotationFailureCode`], a [`SafeDetail`], and the
//! [`TargetEffect`] on the credential in the target. The effect becomes the reported
//! [`RotationSyncState`], which tells the vault whether it is still in sync with the target. A
//! driver that cannot tell whether a change landed must report [`TargetEffect::Unknown`] rather
//! than guess.
//!
//! # Drivers
//!
//! - [`entra`]: Microsoft Entra ID, through Microsoft Graph.
//! - [`scripting`]: an operator-supplied script, run directly or through a PowerShell host.
//!
//! Operator-facing behaviour (required credentials, permissions, the script contract) is
//! documented in the crate README.

pub(crate) mod entra;
pub(crate) mod scripting;

use std::{collections::HashMap, error::Error, sync::Arc};

use async_trait::async_trait;
use bitwarden_pam::{RotationFailureCode, RotationSyncState};
use bitwarden_pam_sealed::SealedTargetSystemKind;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    error::{Retry, SafeDetail},
    resolver::ResolvedCredentials,
};

/// Effect of a failed operation on the target credential, mapped to a [`RotationSyncState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetEffect {
    /// The credential rotation was not applied; target and vault are still in sync.
    NotApplied,
    /// The credential was successfully rotated in the target system.
    Applied,
    /// It is not known whether the rotation was applied (e.g. timeout after send).
    Unknown,
}

impl From<TargetEffect> for RotationSyncState {
    /// The sync state to report for this effect.
    fn from(effect: TargetEffect) -> Self {
        match effect {
            TargetEffect::NotApplied => RotationSyncState::TargetUnchanged,
            TargetEffect::Unknown => RotationSyncState::Indeterminate,
            TargetEffect::Applied => RotationSyncState::TargetUpdated,
        }
    }
}

/// An error returned by any [`Integration`] operation, carrying what the failure report needs.
///
/// Only `retry`, `effect`, `code` and `detail` reach the failure report. `source` holds the raw
/// cause for local debugging and must stay out of both `Display` and anything built from `Debug`
/// for the report: it can contain URLs and account identities.
#[derive(Debug, thiserror::Error)]
#[error("{retry:?}/{effect:?} ({code:?}): {detail}")]
pub(crate) struct IntegrationError {
    pub(crate) retry: Retry,
    pub(crate) effect: TargetEffect,
    pub(crate) code: RotationFailureCode,
    pub(crate) detail: SafeDetail,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl IntegrationError {
    pub(crate) fn new(
        retry: Retry,
        effect: TargetEffect,
        code: RotationFailureCode,
        detail: SafeDetail,
    ) -> Self {
        Self {
            retry,
            effect,
            code,
            detail,
            source: None,
        }
    }

    /// Keeps `cause` for local debugging; it never reaches `Display` or the failure report.
    pub(crate) fn with_source(mut self, cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        self.source = Some(cause.into());
        self
    }
}

/// Input to every [`Integration`] operation, built from the claim and the resolved credentials.
pub(crate) struct RotateContext {
    pub(crate) target_system_id: Uuid,
    /// The opaque account identity string (e.g. a user principal name or object id).
    pub(crate) account_identity: String,
    pub(crate) new_password: String,
    pub(crate) creds: ResolvedCredentials,
    /// Wall-clock time after password generation (step 2); verify checks
    /// `lastPasswordChangeDateTime` against it.
    pub(crate) rotation_started_at: DateTime<Utc>,
}

// Hand-written to keep new_password, creds and account_identity (often a UPN/email) out of the
// output.
impl std::fmt::Debug for RotateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateContext")
            .field("target_system_id", &self.target_system_id)
            .field("account_identity", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("rotation_started_at", &self.rotation_started_at)
            .finish()
    }
}

/// Trait implemented by each target-system driver, such as Entra or CustomScript.
#[async_trait]
pub(crate) trait Integration: Send + Sync {
    /// Rotate the credential to `ctx.new_password`.
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Verify that the rotation applied in the target system.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;

    /// Terminate active sessions for `ctx.account_identity` when the claim's `terminate_sessions`
    /// flag is set. A failure here never fails the rotation.
    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError>;
}

/// Maps a [`SealedTargetSystemKind`] to its [`Integration`] driver. Kinds without a registered
/// integration return `None`, which the executor reports as `unsupported_kind`.
pub(crate) struct IntegrationRegistry {
    map: HashMap<SealedTargetSystemKind, Arc<dyn Integration>>,
}

impl IntegrationRegistry {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub(crate) fn register(
        &mut self,
        kind: SealedTargetSystemKind,
        integration: Arc<dyn Integration>,
    ) {
        self.map.insert(kind, integration);
    }

    pub(crate) fn get(&self, kind: SealedTargetSystemKind) -> Option<Arc<dyn Integration>> {
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
        reg.register(SealedTargetSystemKind::CustomScript, Arc::new(AlwaysOk));
        assert!(reg.get(SealedTargetSystemKind::CustomScript).is_some());
    }

    #[test]
    fn registry_get_unregistered_kind_returns_none() {
        let reg = IntegrationRegistry::new();
        assert!(reg.get(SealedTargetSystemKind::Entra).is_none());
    }

    #[test]
    fn target_effect_variants_exist() {
        let _a = TargetEffect::NotApplied;
        let _b = TargetEffect::Applied;
        let _c = TargetEffect::Unknown;
    }

    #[test]
    fn integration_error_display() {
        let e = IntegrationError::new(
            Retry::Permanent,
            TargetEffect::NotApplied,
            RotationFailureCode::ScriptFailed,
            SafeDetail::from_exit_code(1),
        );
        let s = e.to_string();
        assert!(s.contains("ScriptFailed"));
        assert!(s.contains("exit code 1"));
    }

    #[test]
    fn integration_error_display_excludes_the_source() {
        let e = IntegrationError::new(
            Retry::Transient,
            TargetEffect::Unknown,
            RotationFailureCode::TargetUnreachable,
            SafeDetail::from_kind("NetworkError"),
        )
        .with_source(std::io::Error::other("SECRET-SENTINEL user@example.com"));
        assert!(!e.to_string().contains("SECRET-SENTINEL"));
        let source = Error::source(&e).expect("source is kept");
        assert!(source.to_string().contains("SECRET-SENTINEL"));
    }

    #[test]
    fn rotate_context_debug_redacts_password_and_identity() {
        let ctx = RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: "user@example.com".to_string(),
            new_password: "super-secret-pw".to_string(),
            creds: ResolvedCredentials::new(),
            rotation_started_at: Utc::now(),
        };
        let debug = format!("{ctx:?}");
        assert!(
            !debug.contains("super-secret-pw"),
            "password leaked: {debug}"
        );
        assert!(
            !debug.contains("user@example.com"),
            "account identity leaked: {debug}"
        );
        assert!(debug.contains("REDACTED"));
    }
}
