//! Domain types produced by the [`super`] API wrapper; the wire DTOs come from
//! `bitwarden_api_api::models`.

use bitwarden_api_api::models::{PamPasswordPolicyResponseModel, PamTargetSystemKind};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::session::SessionLost,
    error::{SessionTermination, SyncState},
    policy::PasswordPolicy,
};

/// The target-system kind understood by this connector build. Unrecognised wire values surface as
/// [`TargetKind::Unknown`] instead of failing the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TargetKind {
    /// Microsoft Entra ID (Azure AD).
    Entra,
    /// Microsoft SQL Server (unimplemented in this build).
    Mssql,
    /// Operator-supplied custom rotation script.
    CustomScript,
    /// Any other integer the server returned; treated as unsupported.
    Unknown(i64),
}

impl From<PamTargetSystemKind> for TargetKind {
    fn from(kind: PamTargetSystemKind) -> Self {
        match kind {
            PamTargetSystemKind::Entra => TargetKind::Entra,
            PamTargetSystemKind::Mssql => TargetKind::Mssql,
            PamTargetSystemKind::CustomScript => TargetKind::CustomScript,
            PamTargetSystemKind::__Unknown(v) => TargetKind::Unknown(v),
        }
    }
}

/// Negative lengths, which the wire's `i32` allows, become `None` (unconstrained). Missing flags
/// become `false`.
impl From<PamPasswordPolicyResponseModel> for PasswordPolicy {
    fn from(m: PamPasswordPolicyResponseModel) -> Self {
        let min_length = m.min_length.and_then(|v| u32::try_from(v).ok());
        let max_length = m.max_length.and_then(|v| u32::try_from(v).ok());

        PasswordPolicy {
            min_length,
            max_length,
            include_uppercase: m.include_uppercase.unwrap_or(false),
            include_lowercase: m.include_lowercase.unwrap_or(false),
            include_digits: m.include_digits.unwrap_or(false),
            include_symbols: m.include_symbols.unwrap_or(false),
        }
    }
}

/// A claimable rotation job returned by the poll endpoint.
#[derive(Debug, Clone)]
pub(crate) struct JobRef {
    pub(crate) id: Uuid,
}

/// The work snapshot returned by a successful claim. It carries everything the rotation needs
/// besides the cipher read/write and the outcome report.
#[derive(Debug, Clone)]
pub(crate) struct WorkSnapshot {
    /// Keys every attempt-scoped request (cipher read/write, outcome reports).
    pub(crate) attempt_id: Uuid,
    pub(crate) job_id: Uuid,
    pub(crate) target_system_id: Uuid,
    /// Display name of the target system, for logging.
    pub(crate) target_system_name: String,
    pub(crate) kind: TargetKind,
    pub(crate) password_policy: PasswordPolicy,
    /// For logging; the cipher itself is fetched through the attempt route.
    pub(crate) cipher_id: Uuid,
    /// Opaque account identity passed verbatim to the integration layer.
    pub(crate) account_identity: String,
    pub(crate) terminate_sessions: bool,
    /// Lease deadline: no target-side step starts after it.
    pub(crate) execute_by: DateTime<Utc>,
}

/// The cipher snapshot returned by the cipher-read endpoint.
#[derive(Debug, Clone)]
pub(crate) struct RotationCipher {
    pub(crate) cipher_id: Uuid,
    /// Parsed from the wire string at the API boundary, so the crypto layer can replace one field.
    pub(crate) data: serde_json::Value,
    /// Per-item cipher key (EncString), present when the item has its own key.
    pub(crate) key: Option<String>,
    /// Echoed back verbatim as `lastKnownRevisionDate` on the cipher write, for optimistic
    /// concurrency.
    pub(crate) revision_date: String,
}

impl From<SessionTermination> for bitwarden_api_api::models::PamSessionTerminationOutcome {
    fn from(t: SessionTermination) -> Self {
        match t {
            SessionTermination::NotRequested => {
                bitwarden_api_api::models::PamSessionTerminationOutcome::NotRequested
            }
            SessionTermination::Terminated => {
                bitwarden_api_api::models::PamSessionTerminationOutcome::Terminated
            }
            SessionTermination::TermFailed => {
                bitwarden_api_api::models::PamSessionTerminationOutcome::TermFailed
            }
        }
    }
}

impl From<SyncState> for bitwarden_api_api::models::PamRotationSyncState {
    fn from(s: SyncState) -> Self {
        match s {
            SyncState::TargetUnchanged => {
                bitwarden_api_api::models::PamRotationSyncState::TargetUnchanged
            }
            SyncState::TargetUpdated => {
                bitwarden_api_api::models::PamRotationSyncState::TargetUpdated
            }
            SyncState::Indeterminate => {
                bitwarden_api_api::models::PamRotationSyncState::Indeterminate
            }
        }
    }
}

/// Errors returned by the [`super::RotationApi`] wrapper. They never include response bodies, which
/// can contain sensitive data.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// The connector's session was terminally lost (revoked or closed).
    SessionLost(SessionLost),

    /// The server returned 409. A claim maps it to `Ok(None)` instead; on a cipher write it means
    /// revision drift or capability lost.
    Rejected {
        /// The HTTP status, typically 409.
        status: u16,
    },

    /// A 404 on an attempt-scoped route (`/cipher`, `/success`, `/failure`): the server does not
    /// know the attempt, so the executor abandons it unreported.
    UnknownAttempt,

    /// A 404 on a connector or job route: the server does not consider this connector eligible. The
    /// executor runs a refresh probe to tell this apart from `CredentialRefused`.
    NotEligible,

    /// A transport error, 429, 5xx, a 401 that survived the refresh retry, or any other unexpected
    /// status. The message is a bounded status or error kind, never body content.
    Transient(String),

    /// The response could not be decoded or lacked a required field. The message never includes
    /// payload content.
    Protocol(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLost(l) => write!(f, "session lost: {l:?}"),
            Self::Rejected { status } => write!(f, "rejected (HTTP {status})"),
            Self::UnknownAttempt => write!(f, "attempt not found (404)"),
            Self::NotEligible => {
                write!(f, "access connector not eligible (404 on connector route)")
            }
            Self::Transient(s) => write!(f, "transient error: {s}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kind_from_entra() {
        assert_eq!(
            TargetKind::from(PamTargetSystemKind::Entra),
            TargetKind::Entra
        );
    }

    #[test]
    fn target_kind_from_mssql() {
        assert_eq!(
            TargetKind::from(PamTargetSystemKind::Mssql),
            TargetKind::Mssql
        );
    }

    #[test]
    fn target_kind_from_custom_script() {
        assert_eq!(
            TargetKind::from(PamTargetSystemKind::CustomScript),
            TargetKind::CustomScript
        );
    }

    #[test]
    fn target_kind_from_unknown_variant() {
        assert_eq!(
            TargetKind::from(PamTargetSystemKind::__Unknown(99)),
            TargetKind::Unknown(99)
        );
    }

    #[test]
    fn password_policy_from_full_model() {
        let m = PamPasswordPolicyResponseModel {
            min_length: Some(8),
            max_length: Some(64),
            include_uppercase: Some(true),
            include_lowercase: Some(true),
            include_digits: Some(false),
            include_symbols: Some(true),
        };
        let p = PasswordPolicy::from(m);
        assert_eq!(p.min_length, Some(8));
        assert_eq!(p.max_length, Some(64));
        assert!(p.include_uppercase);
        assert!(p.include_lowercase);
        assert!(!p.include_digits);
        assert!(p.include_symbols);
    }

    #[test]
    fn password_policy_negative_lengths_become_none() {
        let m = PamPasswordPolicyResponseModel {
            min_length: Some(-1),
            max_length: Some(-5),
            include_uppercase: Some(true),
            include_lowercase: Some(false),
            include_digits: Some(false),
            include_symbols: Some(false),
        };
        let p = PasswordPolicy::from(m);
        assert_eq!(p.min_length, None, "negative min should become None");
        assert_eq!(p.max_length, None, "negative max should become None");
    }

    #[test]
    fn password_policy_none_booleans_default_to_false() {
        let m = PamPasswordPolicyResponseModel {
            min_length: None,
            max_length: None,
            include_uppercase: None,
            include_lowercase: None,
            include_digits: None,
            include_symbols: None,
        };
        let p = PasswordPolicy::from(m);
        assert_eq!(p.min_length, None);
        assert_eq!(p.max_length, None);
        assert!(!p.include_uppercase);
        assert!(!p.include_lowercase);
        assert!(!p.include_digits);
        assert!(!p.include_symbols);
    }

    #[test]
    fn session_termination_not_requested() {
        let out = bitwarden_api_api::models::PamSessionTerminationOutcome::from(
            SessionTermination::NotRequested,
        );
        assert_eq!(
            out,
            bitwarden_api_api::models::PamSessionTerminationOutcome::NotRequested
        );
        assert_eq!(out.as_i64(), 0);
    }

    #[test]
    fn session_termination_terminated() {
        let out = bitwarden_api_api::models::PamSessionTerminationOutcome::from(
            SessionTermination::Terminated,
        );
        assert_eq!(
            out,
            bitwarden_api_api::models::PamSessionTerminationOutcome::Terminated
        );
        assert_eq!(out.as_i64(), 1);
    }

    #[test]
    fn session_termination_term_failed() {
        let out = bitwarden_api_api::models::PamSessionTerminationOutcome::from(
            SessionTermination::TermFailed,
        );
        assert_eq!(
            out,
            bitwarden_api_api::models::PamSessionTerminationOutcome::TermFailed
        );
        assert_eq!(out.as_i64(), 2);
    }

    #[test]
    fn sync_state_target_unchanged() {
        let out = bitwarden_api_api::models::PamRotationSyncState::from(SyncState::TargetUnchanged);
        assert_eq!(
            out,
            bitwarden_api_api::models::PamRotationSyncState::TargetUnchanged
        );
        assert_eq!(out.as_i64(), 0);
    }

    #[test]
    fn sync_state_target_updated() {
        let out = bitwarden_api_api::models::PamRotationSyncState::from(SyncState::TargetUpdated);
        assert_eq!(
            out,
            bitwarden_api_api::models::PamRotationSyncState::TargetUpdated
        );
        assert_eq!(out.as_i64(), 1);
    }

    #[test]
    fn sync_state_indeterminate() {
        let out = bitwarden_api_api::models::PamRotationSyncState::from(SyncState::Indeterminate);
        assert_eq!(
            out,
            bitwarden_api_api::models::PamRotationSyncState::Indeterminate
        );
        assert_eq!(out.as_i64(), 2);
    }
}
