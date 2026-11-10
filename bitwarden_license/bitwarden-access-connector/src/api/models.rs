//! Domain types produced by the [`super`] API wrapper; the wire DTOs come from
//! `bitwarden_api_api::models`.

use bitwarden_pam_sealed::SealedTargetSystemKind;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::session::SessionLost,
    error::{SessionTermination, SyncState},
};

/// The target-system kind, taken only from the unsealed blob, never the claim's plaintext `kind`.
/// An unrecognised kind fails to unseal, so there is no catch-all variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TargetKind {
    /// Microsoft Entra ID (Azure AD).
    Entra,
    /// Microsoft SQL Server (unimplemented in this build).
    Mssql,
    /// Operator-supplied custom rotation script.
    CustomScript,
}

impl From<SealedTargetSystemKind> for TargetKind {
    fn from(kind: SealedTargetSystemKind) -> Self {
        match kind {
            SealedTargetSystemKind::Entra => TargetKind::Entra,
            SealedTargetSystemKind::Mssql => TargetKind::Mssql,
            SealedTargetSystemKind::CustomScript => TargetKind::CustomScript,
        }
    }
}

/// A claimable rotation job returned by the poll endpoint.
#[derive(Debug, Clone)]
pub(crate) struct JobRef {
    pub(crate) id: Uuid,
}

/// The work snapshot returned by a successful claim; `executor::verify` checks it before any field
/// is trusted.
#[derive(Debug, Clone)]
pub(crate) struct WorkSnapshot {
    /// Keys every attempt-scoped request (cipher read/write, outcome reports).
    pub(crate) attempt_id: Uuid,
    pub(crate) job_id: Uuid,
    pub(crate) target_system_id: Uuid,
    /// For logging only.
    pub(crate) target_system_name: String,
    pub(crate) cipher_id: Uuid,
    pub(crate) target_system_sealed_data: Option<String>,
    pub(crate) target_system_wrapped_key: Option<String>,
    pub(crate) rotation_config_sealed_data: Option<String>,
    pub(crate) rotation_config_wrapped_key: Option<String>,
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
            TargetKind::from(SealedTargetSystemKind::Entra),
            TargetKind::Entra
        );
    }

    #[test]
    fn target_kind_from_mssql() {
        assert_eq!(
            TargetKind::from(SealedTargetSystemKind::Mssql),
            TargetKind::Mssql
        );
    }

    #[test]
    fn target_kind_from_custom_script() {
        assert_eq!(
            TargetKind::from(SealedTargetSystemKind::CustomScript),
            TargetKind::CustomScript
        );
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
