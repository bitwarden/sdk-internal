//! Microsoft Entra ID (Azure AD) integration for credential rotation.
//!
//! This module is currently a stub.  The full implementation will use the
//! Microsoft Graph REST API via the api-base HTTP builder for rotate, verify,
//! and terminate_sessions operations.
//!
//! See plan §7 for the full design, including URL-building security (no path
//! interpolation of `account_identity`), required Graph permissions, and the
//! verify-probe flag.

use async_trait::async_trait;

use crate::error::{ErrorClass, FailureCode, SafeDetail};

use super::{Integration, IntegrationError, RotateContext, TargetEffect};

// ---------------------------------------------------------------------------
// EntraIntegration
// ---------------------------------------------------------------------------

/// Microsoft Entra ID integration driver.
///
/// Rotates credentials via the Graph API using the administrative password-reset
/// endpoint (`PATCH /v1.0/users/{id}/passwordProfile`).
///
/// # Security note
///
/// `account_identity` is attacker-influencable input; it is NEVER interpolated
/// into URL path strings.  URL building uses `Url::path_segments_mut().push(id)`
/// so it is treated as a single percent-encoded path segment.
pub(crate) struct EntraIntegration {
    /// Whether to perform an ROPC verify probe after rotation.
    ///
    /// The probe is disabled by default because MFA / Conditional Access
    /// blocks it in most tenants.  Enable with `--entra-verify-probe`.
    #[allow(dead_code)]
    verify_probe: bool,
}

impl EntraIntegration {
    /// Build a new `EntraIntegration`.
    pub(crate) fn new(verify_probe: bool) -> Self {
        Self { verify_probe }
    }
}

#[async_trait]
impl Integration for EntraIntegration {
    async fn rotate(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::UnsupportedKind,
            detail: SafeDetail::from_kind("EntraNotImplemented"),
        })
    }

    async fn verify(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::Applied,
            code: FailureCode::UnsupportedKind,
            detail: SafeDetail::from_kind("EntraNotImplemented"),
        })
    }

    async fn terminate_sessions(&self, _ctx: &RotateContext) -> Result<(), IntegrationError> {
        Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::UnsupportedKind,
            detail: SafeDetail::from_kind("EntraNotImplemented"),
        })
    }
}
