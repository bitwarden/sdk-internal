//! Local domain types produced by the [`super`] API wrapper layer.
//!
//! Wire DTOs come from `bitwarden_api_api::models`; only the stripped-down
//! daemon-local types live here.

use bitwarden_api_api::models::{PamPasswordPolicyResponseModel, PamTargetSystemKind};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::session::SessionLost,
    error::{SessionTermination, SyncState},
    policy::PasswordPolicy,
};

/// The target-system kind understood by this daemon build.
///
/// Unknown or future variants, including `Mssql` (wire-known but not yet
/// implemented), surface as [`TargetKind::Unknown`] rather than crashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TargetKind {
    /// Microsoft Entra ID (formerly Azure AD).
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

/// Converts the generated [`PamPasswordPolicyResponseModel`] into the daemon's
/// [`PasswordPolicy`].
///
/// Negative length values are treated as `None` (unconstrained), since the
/// wire's `Option<i32>` allows them but a negative length is not meaningful.
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

/// A reference to a claimable rotation job returned by the poll endpoint.
///
/// The daemon iterates over these and attempts to claim each one until it
/// succeeds (or the list is exhausted).
#[derive(Debug, Clone)]
pub(crate) struct JobRef {
    /// The rotation job UUID used in the claim request.
    pub(crate) id: Uuid,
}

/// The self-contained work snapshot returned by a successful claim.
///
/// Contains everything the daemon needs to execute the rotation without any
/// further round-trips to the server (except the cipher read/write and the
/// outcome report).
#[derive(Debug, Clone)]
pub(crate) struct WorkSnapshot {
    /// The attempt UUID used for all subsequent attempt-scoped requests
    /// (cipher read/write, success/failure reports).
    pub(crate) attempt_id: Uuid,
    /// The job UUID associated with this claim.
    pub(crate) job_id: Uuid,
    /// The target system UUID identifying which system to rotate on.
    pub(crate) target_system_id: Uuid,
    /// Human-readable name of the target system (for logging).
    pub(crate) target_system_name: String,
    /// Kind of target system (determines which integration to use).
    pub(crate) kind: TargetKind,
    /// Password policy that governs the generated credential.
    pub(crate) password_policy: PasswordPolicy,
    /// The cipher UUID that holds the current credential (used for logging /
    /// correlation; the actual cipher is fetched via the attempt route).
    pub(crate) cipher_id: Uuid,
    /// Opaque account identity passed verbatim to the integration layer.
    pub(crate) account_identity: String,
    /// Whether to terminate active sessions after rotating the credential.
    pub(crate) terminate_sessions: bool,
    /// Lease deadline: the daemon **must** keep heartbeating (or complete)
    /// before this instant, or the server may reclaim the job.
    pub(crate) execute_by: DateTime<Utc>,
}

/// The cipher snapshot returned by the cipher-read endpoint.
///
/// The `data` field holds the cipher's encrypted JSON blob parsed into a
/// [`serde_json::Value`] so the crypto layer can apply a JSON-pointer update
/// without re-serialising the whole structure from scratch.
#[derive(Debug, Clone)]
pub(crate) struct RotationCipher {
    /// The cipher UUID (for logging / correlation).
    pub(crate) cipher_id: Uuid,
    /// The cipher's encrypted JSON blob, parsed from the wire string.
    ///
    /// Parsed at the API boundary so the crypto layer can treat it as
    /// structured JSON; a decode failure is [`super::ApiError::Protocol`],
    /// never echoing content.
    pub(crate) data: serde_json::Value,
    /// Optional per-item cipher key (EncString), present with item-level key
    /// wrapping.
    pub(crate) key: Option<String>,
    /// The revision date string (RFC-3339), echoed back verbatim on the cipher
    /// write as `lastKnownRevisionDate` for optimistic-concurrency enforcement.
    pub(crate) revision_date: String,
}

/// Convert the daemon's `SessionTermination` into the generated
/// [`bitwarden_api_api::models::PamSessionTerminationOutcome`] integer enum.
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

/// Convert the daemon's `SyncState` into the generated
/// [`bitwarden_api_api::models::PamRotationSyncState`] integer enum.
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

/// Errors returned by the [`super::RotationApi`] wrapper.
///
/// Each variant maps to a distinct server or transport condition. Response
/// bodies are never included; they can contain sensitive data.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// The daemon's session was terminally lost (revoked or closed).
    ///
    /// Returned by `SessionManager::bearer` or `force_refresh` as
    /// [`crate::auth::session::SessionError::Lost`]; the executor then consults
    /// `session.phase()` to decide whether to exit or pause.
    SessionLost(SessionLost),

    /// The server returned 409 (conflict or race lost on a claim) or an analogous rejection.
    ///
    /// For the claim endpoint, this maps to `Ok(None)` instead (another daemon won the race);
    /// for cipher-write, it means revision drift or capability lost.
    Rejected {
        /// The HTTP status code of the rejection (typically 409).
        status: u16,
    },

    /// The server returned 404 for an attempt-scoped route (`/cipher`,
    /// `/success`, `/failure`): the attempt is no longer known to the server.
    /// The executor should abort the rotation unreported.
    UnknownAttempt,

    /// The daemon is not eligible to use the rotation endpoints.
    ///
    /// The server's `DaemonRequestEndpointFilter` returns 404 on any daemon route for a
    /// revoked PAM license, a disabled daemon, or `UsePam` off; the executor runs a
    /// refresh-probe before choosing between `CredentialRefused` and `NotEligible`.
    NotEligible,

    /// A transient error: network failure, 429, 5xx, or a 401 that persisted
    /// after the single refresh-and-retry.
    ///
    /// The description is a bounded status/error-kind string; no response
    /// body content.
    Transient(String),

    /// A protocol error: the server's response could not be decoded, or a
    /// required field was missing or of an unexpected shape.
    ///
    /// Content of the failed payload is never included in the message.
    Protocol(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLost(l) => write!(f, "session lost: {l:?}"),
            Self::Rejected { status } => write!(f, "rejected (HTTP {status})"),
            Self::UnknownAttempt => write!(f, "attempt not found (404)"),
            Self::NotEligible => write!(f, "daemon not eligible (404 on daemon route)"),
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
