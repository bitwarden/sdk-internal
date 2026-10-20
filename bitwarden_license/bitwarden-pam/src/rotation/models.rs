use bitwarden_api_api::models::{
    PamAccessConnectorStatus as ApiAccessConnectorStatus, PamRotationAttemptResponseModel,
    PamRotationAttemptStatus as ApiRotationAttemptStatus, PamRotationJobResponseModel,
    PamRotationJobStatus as ApiRotationJobStatus, PamRotationSource as ApiRotationSource,
    PamRotationSyncState as ApiRotationSyncState,
    PamSessionTerminationOutcome as ApiSessionTerminationOutcome,
    PamTargetSystemMethod as ApiTargetSystemMethod, PamTargetSystemStatus as ApiTargetSystemStatus,
};
use bitwarden_core::require;
use bitwarden_pam_sealed::{
    PasswordPolicyError, SealedPasswordPolicy, SealedTargetSystemKind, SealedTargetSystemMethod,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::error::RotationError;
use crate::{AccessConnectorId, RotationAttemptId, RotationConfigId, RotationJobId};

/// Lifecycle state of an access connector. Removing a connector for good is a delete, not a
/// status.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum AccessConnectorStatus {
    /// The connector may authenticate and claim rotation jobs.
    Enabled,
    /// The connector cannot authenticate or claim jobs. Its credential is kept so it can be
    /// re-enabled.
    Disabled,
    /// A status this SDK version does not recognize. Kept as a distinct variant so listing
    /// connectors never fails against a newer server.
    Unknown,
}

impl From<ApiAccessConnectorStatus> for AccessConnectorStatus {
    fn from(status: ApiAccessConnectorStatus) -> Self {
        match status {
            ApiAccessConnectorStatus::Enabled => Self::Enabled,
            ApiAccessConnectorStatus::Disabled => Self::Disabled,
            ApiAccessConnectorStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// How a target system's credential is rotated.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum TargetSystemMethod {
    /// A connector writes the new secret directly into the target system.
    Automatic,
    /// An operator applies the new credential out-of-band; the config records the event.
    Manual,
    /// A method this SDK version does not recognize.
    Unknown,
}

impl From<ApiTargetSystemMethod> for TargetSystemMethod {
    fn from(method: ApiTargetSystemMethod) -> Self {
        match method {
            ApiTargetSystemMethod::Automatic => Self::Automatic,
            ApiTargetSystemMethod::Manual => Self::Manual,
            ApiTargetSystemMethod::__Unknown(_) => Self::Unknown,
        }
    }
}

impl TryFrom<TargetSystemMethod> for ApiTargetSystemMethod {
    type Error = RotationError;

    fn try_from(method: TargetSystemMethod) -> Result<Self, Self::Error> {
        match method {
            TargetSystemMethod::Automatic => Ok(Self::Automatic),
            TargetSystemMethod::Manual => Ok(Self::Manual),
            // `Unknown` carries no wire value to send back.
            TargetSystemMethod::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }
}

/// The technology a target system represents. Only meaningful for
/// [`Automatic`](TargetSystemMethod::Automatic) systems; a manual rotation has no integration.
/// Lives only in the sealed blob.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum TargetSystemKind {
    /// Entra ID / Azure AD service-account password rotation.
    Entra,
    /// An operator-supplied script run by the connector.
    CustomScript,
    /// A kind this SDK version does not recognize.
    Unknown,
}

impl From<SealedTargetSystemMethod> for TargetSystemMethod {
    fn from(method: SealedTargetSystemMethod) -> Self {
        match method {
            SealedTargetSystemMethod::Automatic => Self::Automatic,
            SealedTargetSystemMethod::Manual => Self::Manual,
        }
    }
}

impl From<SealedTargetSystemKind> for TargetSystemKind {
    fn from(kind: SealedTargetSystemKind) -> Self {
        match kind {
            SealedTargetSystemKind::Entra => Self::Entra,
            SealedTargetSystemKind::CustomScript => Self::CustomScript,
        }
    }
}

impl TryFrom<TargetSystemKind> for SealedTargetSystemKind {
    type Error = RotationError;

    fn try_from(kind: TargetSystemKind) -> Result<Self, Self::Error> {
        match kind {
            TargetSystemKind::Entra => Ok(Self::Entra),
            TargetSystemKind::CustomScript => Ok(Self::CustomScript),
            TargetSystemKind::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }
}

/// Lifecycle state of a target system.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum TargetSystemStatus {
    /// The target system accepts rotation jobs.
    Active,
    /// No new rotation jobs are dispatched; jobs already in flight run to completion.
    Disabled,
    /// Registered but not yet sealed, left by a failed [`TargetSystemsClient::create`].
    /// [`TargetSystemsClient::update`] finishes sealing; [`TargetSystemsClient::delete`]
    /// discards it.
    ///
    /// [`TargetSystemsClient::create`]: super::TargetSystemsClient::create
    /// [`TargetSystemsClient::update`]: super::TargetSystemsClient::update
    /// [`TargetSystemsClient::delete`]: super::TargetSystemsClient::delete
    PendingSeal,
    /// A status this SDK version does not recognize.
    Unknown,
}

impl From<ApiTargetSystemStatus> for TargetSystemStatus {
    fn from(status: ApiTargetSystemStatus) -> Self {
        match status {
            ApiTargetSystemStatus::Active => Self::Active,
            ApiTargetSystemStatus::Disabled => Self::Disabled,
            ApiTargetSystemStatus::PendingSeal => Self::PendingSeal,
            ApiTargetSystemStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// What triggered a rotation job.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationSource {
    /// The cron schedule fired.
    Scheduled,
    /// An operator asked for a rotation now.
    OnDemand,
    /// An access lease ended on a config with `rotate_on_access_end` set.
    AccessEnd,
    /// A source this SDK version does not recognize.
    Unknown,
}

impl From<ApiRotationSource> for RotationSource {
    fn from(source: ApiRotationSource) -> Self {
        match source {
            ApiRotationSource::Scheduled => Self::Scheduled,
            ApiRotationSource::OnDemand => Self::OnDemand,
            ApiRotationSource::AccessEnd => Self::AccessEnd,
            ApiRotationSource::__Unknown(_) => Self::Unknown,
        }
    }
}

/// Overall status of a rotation job.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationJobStatus {
    /// Queued and waiting for a connector to claim it.
    Pending,
    /// A connector is executing the job.
    Claimed,
    /// An attempt succeeded and updated the vault cipher.
    Succeeded,
    /// The job exhausted its retry budget.
    Failed,
    /// The job passed its deadline without a successful attempt.
    TimedOut,
    /// A status this SDK version does not recognize.
    Unknown,
}

impl From<ApiRotationJobStatus> for RotationJobStatus {
    fn from(status: ApiRotationJobStatus) -> Self {
        match status {
            ApiRotationJobStatus::Pending => Self::Pending,
            ApiRotationJobStatus::Claimed => Self::Claimed,
            ApiRotationJobStatus::Succeeded => Self::Succeeded,
            ApiRotationJobStatus::Failed => Self::Failed,
            ApiRotationJobStatus::TimedOut => Self::TimedOut,
            ApiRotationJobStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// Per-attempt outcome within a rotation job.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationAttemptStatus {
    /// The connector is actively running this attempt.
    Executing,
    /// The target system accepted the new credential and the vault cipher was updated.
    Rotated,
    /// The attempt failed; see [`RotationAttempt::failure_reason`].
    Errored,
    /// The job was released or timed out mid-attempt; this does not count against the retry
    /// budget.
    Abandoned,
    /// A status this SDK version does not recognize.
    Unknown,
}

impl From<ApiRotationAttemptStatus> for RotationAttemptStatus {
    fn from(status: ApiRotationAttemptStatus) -> Self {
        match status {
            ApiRotationAttemptStatus::Executing => Self::Executing,
            ApiRotationAttemptStatus::Rotated => Self::Rotated,
            ApiRotationAttemptStatus::Errored => Self::Errored,
            ApiRotationAttemptStatus::Abandoned => Self::Abandoned,
            ApiRotationAttemptStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// Whether a failed rotation attempt left the target system's credential changed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationSyncState {
    /// The target's credential is unchanged, so the vault still matches it.
    TargetUnchanged,
    /// The target accepted the new credential but the vault was not updated, so they disagree.
    TargetUpdated,
    /// The target-system call may or may not have applied (network error or timeout). No vault
    /// write was attempted, so the vault and the target may disagree until the next rotation.
    Indeterminate,
    /// A state this SDK version does not recognize.
    Unknown,
}

impl From<ApiRotationSyncState> for RotationSyncState {
    fn from(state: ApiRotationSyncState) -> Self {
        match state {
            ApiRotationSyncState::TargetUnchanged => Self::TargetUnchanged,
            ApiRotationSyncState::TargetUpdated => Self::TargetUpdated,
            ApiRotationSyncState::Indeterminate => Self::Indeterminate,
            ApiRotationSyncState::__Unknown(_) => Self::Unknown,
        }
    }
}

impl TryFrom<RotationSyncState> for ApiRotationSyncState {
    type Error = RotationError;

    fn try_from(state: RotationSyncState) -> Result<Self, Self::Error> {
        match state {
            RotationSyncState::TargetUnchanged => Ok(Self::TargetUnchanged),
            RotationSyncState::TargetUpdated => Ok(Self::TargetUpdated),
            RotationSyncState::Indeterminate => Ok(Self::Indeterminate),
            RotationSyncState::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }
}

/// Whether the connector terminated the account's active sessions after rotating.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum SessionTerminationOutcome {
    /// Session termination was not requested for this config.
    NotRequested,
    /// The sessions were terminated.
    Terminated,
    /// Termination was requested but failed. The rotation itself still succeeded.
    TermFailed,
    /// An outcome this SDK version does not recognize.
    Unknown,
}

impl From<ApiSessionTerminationOutcome> for SessionTerminationOutcome {
    fn from(outcome: ApiSessionTerminationOutcome) -> Self {
        match outcome {
            ApiSessionTerminationOutcome::NotRequested => Self::NotRequested,
            ApiSessionTerminationOutcome::Terminated => Self::Terminated,
            ApiSessionTerminationOutcome::TermFailed => Self::TermFailed,
            ApiSessionTerminationOutcome::__Unknown(_) => Self::Unknown,
        }
    }
}

impl TryFrom<SessionTerminationOutcome> for ApiSessionTerminationOutcome {
    type Error = RotationError;

    fn try_from(outcome: SessionTerminationOutcome) -> Result<Self, Self::Error> {
        match outcome {
            SessionTerminationOutcome::NotRequested => Ok(Self::NotRequested),
            SessionTerminationOutcome::Terminated => Ok(Self::Terminated),
            SessionTerminationOutcome::TermFailed => Ok(Self::TermFailed),
            SessionTerminationOutcome::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }
}

/// Why a rotation attempt failed, as the connector reports it. On the wire it is a snake_case
/// token, which the server stores as the start of [`RotationAttempt::failure_reason`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationFailureCode {
    /// No active session at the start of execution (terminal session state).
    NoActiveSession,
    /// Target-system credentials could not be resolved from the configured resolver.
    CredentialsUnresolved,
    /// The password policy received from the server is invalid or cannot be satisfied.
    InvalidPolicy,
    /// The target-system kind is not supported by this connector build.
    UnsupportedKind,
    /// The target system rejected the rotation (e.g. wrong account, policy violation at the
    /// target).
    TargetRejected,
    /// The target system could not be reached (network or connectivity error).
    TargetUnreachable,
    /// Verification of the rotated credential failed after the rotation step.
    VerificationFailed,
    /// A custom script exited with a failure code.
    ScriptFailed,
    /// A custom script exceeded its configured timeout.
    ScriptTimeout,
    /// The server rejected the cipher write (e.g. revision-date conflict).
    CipherWriteRejected,
    /// Encrypting the updated cipher data failed.
    CipherEncryptFailed,
    /// A sealed-data check (1-8) failed; see [`WorkSnapshot::verify`](crate::WorkSnapshot::verify).
    SealedDataRejected,
    /// An unexpected internal error occurred.
    Internal,
    /// A code this SDK version does not recognize.
    Unknown,
}

impl RotationFailureCode {
    /// The wire token the server stores for this code, at most 100 characters. Refuses
    /// [`Unknown`](Self::Unknown), which has no token to send.
    pub fn as_token(self) -> Result<&'static str, RotationError> {
        match self {
            Self::NoActiveSession => Ok("no_active_session"),
            Self::CredentialsUnresolved => Ok("credentials_unresolved"),
            Self::InvalidPolicy => Ok("invalid_policy"),
            Self::UnsupportedKind => Ok("unsupported_kind"),
            Self::TargetRejected => Ok("target_rejected"),
            Self::TargetUnreachable => Ok("target_unreachable"),
            Self::VerificationFailed => Ok("verification_failed"),
            Self::ScriptFailed => Ok("script_failed"),
            Self::ScriptTimeout => Ok("script_timeout"),
            Self::CipherWriteRejected => Ok("cipher_write_rejected"),
            Self::CipherEncryptFailed => Ok("cipher_encrypt_failed"),
            Self::SealedDataRejected => Ok("sealed_data_rejected"),
            Self::Internal => Ok("internal"),
            Self::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }

    /// Parses a wire token; an unrecognized token, including `"unknown"`, is
    /// [`Unknown`](Self::Unknown).
    pub fn from_token(token: &str) -> Self {
        match token {
            "no_active_session" => Self::NoActiveSession,
            "credentials_unresolved" => Self::CredentialsUnresolved,
            "invalid_policy" => Self::InvalidPolicy,
            "unsupported_kind" => Self::UnsupportedKind,
            "target_rejected" => Self::TargetRejected,
            "target_unreachable" => Self::TargetUnreachable,
            "verification_failed" => Self::VerificationFailed,
            "script_failed" => Self::ScriptFailed,
            "script_timeout" => Self::ScriptTimeout,
            "cipher_write_rejected" => Self::CipherWriteRejected,
            "cipher_encrypt_failed" => Self::CipherEncryptFailed,
            "sealed_data_rejected" => Self::SealedDataRejected,
            "internal" => Self::Internal,
            _ => Self::Unknown,
        }
    }
}

/// Password generation policy for a target system. For [`Manual`](TargetSystemMethod::Manual)
/// systems it is guidance for the operator that nothing enforces.
/// Lives only in the sealed blob.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    /// Minimum length of a generated credential.
    pub min_length: u32,
    /// Maximum length of a generated credential.
    pub max_length: u32,
    /// Whether generated credentials may include `A-Z`.
    pub include_uppercase: bool,
    /// Whether generated credentials may include `a-z`.
    pub include_lowercase: bool,
    /// Whether generated credentials may include `0-9`.
    pub include_digits: bool,
    /// Whether generated credentials may include punctuation.
    pub include_symbols: bool,
}

impl PasswordPolicy {
    /// Validates that the generator can produce a password for this policy. The access connector
    /// applies the same check, so an unsatisfiable policy is caught while editing rather than at
    /// rotation.
    pub(crate) fn validate(&self) -> Result<(), PasswordPolicyError> {
        SealedPasswordPolicy::from(self.clone()).validate()
    }
}

impl From<SealedPasswordPolicy> for PasswordPolicy {
    fn from(policy: SealedPasswordPolicy) -> Self {
        Self {
            min_length: policy.min_length,
            max_length: policy.max_length,
            include_uppercase: policy.include_uppercase,
            include_lowercase: policy.include_lowercase,
            include_digits: policy.include_digits,
            include_symbols: policy.include_symbols,
        }
    }
}

impl From<PasswordPolicy> for SealedPasswordPolicy {
    fn from(policy: PasswordPolicy) -> Self {
        Self {
            min_length: policy.min_length,
            max_length: policy.max_length,
            include_uppercase: policy.include_uppercase,
            include_lowercase: policy.include_lowercase,
            include_digits: policy.include_digits,
            include_symbols: policy.include_symbols,
        }
    }
}

/// One connector's execution of the rotation sequence for a job.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationAttempt {
    /// The attempt's unique identifier.
    pub id: RotationAttemptId,
    /// The job this attempt belongs to.
    pub job_id: RotationJobId,
    /// The connector that ran this attempt. `None` on a payload the server did not attribute.
    pub claimed_by_access_connector_id: Option<AccessConnectorId>,
    /// Current execution state of the attempt.
    pub status: RotationAttemptStatus,
    /// Operator-facing failure reason, set for an errored attempt. Reported by the connector and
    /// never raw target output; treat it as untrusted text for display only.
    pub failure_reason: Option<String>,
    /// The code at the start of [`failure_reason`](Self::failure_reason). `None` when there is no
    /// reason; [`Unknown`](RotationFailureCode::Unknown) when the code is not one this SDK
    /// recognizes.
    pub failure_code: Option<RotationFailureCode>,
    /// Whether the vault cipher was written with the rotated credential.
    pub cipher_updated: bool,
    /// Whether a failure left the target's credential changed. `None` unless the attempt errored.
    pub sync_state: Option<RotationSyncState>,
    /// Whether active sessions were terminated after rotating. `None` unless the attempt rotated.
    pub session_termination: Option<SessionTerminationOutcome>,
    /// The connector's start time for this attempt (UTC).
    pub started_at: DateTime<Utc>,
    /// The attempt's resolution time (UTC), or `None` while still executing.
    pub ended_at: Option<DateTime<Utc>>,
}

impl TryFrom<PamRotationAttemptResponseModel> for RotationAttempt {
    type Error = RotationError;

    fn try_from(response: PamRotationAttemptResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: RotationAttemptId::new(require!(response.id)),
            job_id: RotationJobId::new(require!(response.job_id)),
            claimed_by_access_connector_id: response
                .claimed_by_access_connector_id
                .map(AccessConnectorId::new),
            status: require!(response.status).into(),
            failure_code: response
                .failure_reason
                .as_deref()
                .map(failure_code_from_reason),
            failure_reason: response.failure_reason,
            cipher_updated: response.cipher_updated.unwrap_or(false),
            sync_state: response.sync_state.map(Into::into),
            session_termination: response.session_termination.map(Into::into),
            started_at: require!(response.creation_date).parse()?,
            ended_at: response
                .resolved_date
                .map(|date| date.parse())
                .transpose()?,
        })
    }
}

/// The server builds the reason as `ErrorCode` or `ErrorCode: Detail`.
fn failure_code_from_reason(reason: &str) -> RotationFailureCode {
    let token = reason.split_once(": ").map_or(reason, |(code, _)| code);
    RotationFailureCode::from_token(token)
}

/// One dispatch of the rotation workflow for a config. Each claim records an attempt, so a retried
/// or released job carries several.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationJob {
    /// The job's unique identifier.
    pub id: RotationJobId,
    /// The rotation config this job was dispatched for.
    pub rotation_config_id: RotationConfigId,
    /// What triggered the job.
    pub source: RotationSource,
    /// Current lifecycle state of the job.
    pub status: RotationJobStatus,
    /// The connector holding the job; `None` while unclaimed.
    pub claimed_by_access_connector_id: Option<AccessConnectorId>,
    /// The job's claim time (UTC), or `None` while still pending.
    pub claimed_at: Option<DateTime<Utc>>,
    /// The job's queued time (UTC).
    pub created_at: DateTime<Utc>,
    /// The earliest a connector may claim this job again after a released or failed attempt (UTC).
    pub next_claimable_at: Option<DateTime<Utc>>,
    /// The job's claim deadline (UTC); past this it is considered timed out.
    pub expires_at: Option<DateTime<Utc>>,
    /// The job's attempts, oldest first.
    pub attempts: Vec<RotationAttempt>,
}

impl TryFrom<PamRotationJobResponseModel> for RotationJob {
    type Error = RotationError;

    fn try_from(response: PamRotationJobResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: RotationJobId::new(require!(response.id)),
            rotation_config_id: RotationConfigId::new(require!(response.rotation_config_id)),
            source: require!(response.source).into(),
            status: require!(response.status).into(),
            claimed_by_access_connector_id: response
                .claimed_by_access_connector_id
                .map(AccessConnectorId::new),
            claimed_at: response.claimed_at.map(|date| date.parse()).transpose()?,
            created_at: require!(response.creation_date).parse()?,
            next_claimable_at: response
                .next_claimable_at
                .map(|date| date.parse())
                .transpose()?,
            expires_at: response.expires_at.map(|date| date.parse()).transpose()?,
            attempts: response
                .attempts
                .unwrap_or_default()
                .into_iter()
                .map(RotationAttempt::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_CODES: [(RotationFailureCode, &str); 13] = [
        (RotationFailureCode::NoActiveSession, "no_active_session"),
        (
            RotationFailureCode::CredentialsUnresolved,
            "credentials_unresolved",
        ),
        (RotationFailureCode::InvalidPolicy, "invalid_policy"),
        (RotationFailureCode::UnsupportedKind, "unsupported_kind"),
        (RotationFailureCode::TargetRejected, "target_rejected"),
        (RotationFailureCode::TargetUnreachable, "target_unreachable"),
        (
            RotationFailureCode::VerificationFailed,
            "verification_failed",
        ),
        (RotationFailureCode::ScriptFailed, "script_failed"),
        (RotationFailureCode::ScriptTimeout, "script_timeout"),
        (
            RotationFailureCode::CipherWriteRejected,
            "cipher_write_rejected",
        ),
        (
            RotationFailureCode::CipherEncryptFailed,
            "cipher_encrypt_failed",
        ),
        (
            RotationFailureCode::SealedDataRejected,
            "sealed_data_rejected",
        ),
        (RotationFailureCode::Internal, "internal"),
    ];

    #[test]
    fn sync_state_maps_to_api_values() {
        let pairs = [
            (RotationSyncState::TargetUnchanged, 0),
            (RotationSyncState::TargetUpdated, 1),
            (RotationSyncState::Indeterminate, 2),
        ];
        for (state, expected) in pairs {
            let api = ApiRotationSyncState::try_from(state).unwrap();
            assert_eq!(api.as_i64(), expected, "{state:?}");
        }
    }

    #[test]
    fn sync_state_unknown_is_refused() {
        assert!(matches!(
            ApiRotationSyncState::try_from(RotationSyncState::Unknown),
            Err(RotationError::UnrecognizedVariant)
        ));
    }

    #[test]
    fn session_termination_maps_to_api_values() {
        let pairs = [
            (SessionTerminationOutcome::NotRequested, 0),
            (SessionTerminationOutcome::Terminated, 1),
            (SessionTerminationOutcome::TermFailed, 2),
        ];
        for (outcome, expected) in pairs {
            let api = ApiSessionTerminationOutcome::try_from(outcome).unwrap();
            assert_eq!(api.as_i64(), expected, "{outcome:?}");
        }
    }

    #[test]
    fn session_termination_unknown_is_refused() {
        assert!(matches!(
            ApiSessionTerminationOutcome::try_from(SessionTerminationOutcome::Unknown),
            Err(RotationError::UnrecognizedVariant)
        ));
    }

    #[test]
    fn failure_code_tokens_round_trip() {
        for (code, token) in KNOWN_CODES {
            assert_eq!(code.as_token().unwrap(), token, "{code:?}");
            assert_eq!(RotationFailureCode::from_token(token), code);
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{token}\""),
                "{code:?}"
            );
        }
    }

    #[test]
    fn failure_code_tokens_are_bounded_snake_case() {
        for (code, _) in KNOWN_CODES {
            let token = code.as_token().unwrap();
            assert!(token.len() <= 100, "{code:?}");
            assert!(
                token.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{code:?}"
            );
        }
    }

    #[test]
    fn failure_code_unknown_is_refused() {
        assert!(matches!(
            RotationFailureCode::Unknown.as_token(),
            Err(RotationError::UnrecognizedVariant)
        ));
    }

    #[test]
    fn failure_code_unrecognized_token_is_unknown() {
        for token in ["", "from_the_future", "unknown", "Internal"] {
            assert_eq!(
                RotationFailureCode::from_token(token),
                RotationFailureCode::Unknown,
                "{token:?}"
            );
        }
    }

    fn attempt_response(failure_reason: Option<&str>) -> PamRotationAttemptResponseModel {
        PamRotationAttemptResponseModel {
            id: Some(uuid::Uuid::new_v4()),
            job_id: Some(uuid::Uuid::new_v4()),
            status: Some(ApiRotationAttemptStatus::Errored),
            failure_reason: failure_reason.map(str::to_owned),
            creation_date: Some("2026-01-01T00:00:00Z".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn attempt_failure_code_from_code_alone() {
        let attempt = RotationAttempt::try_from(attempt_response(Some("script_timeout"))).unwrap();
        assert_eq!(
            attempt.failure_code,
            Some(RotationFailureCode::ScriptTimeout)
        );
        assert_eq!(attempt.failure_reason.as_deref(), Some("script_timeout"));
    }

    #[test]
    fn attempt_failure_code_from_code_and_detail() {
        let attempt = RotationAttempt::try_from(attempt_response(Some(
            "target_rejected: HTTP 403: forbidden",
        )))
        .unwrap();
        assert_eq!(
            attempt.failure_code,
            Some(RotationFailureCode::TargetRejected)
        );
        assert_eq!(
            attempt.failure_reason.as_deref(),
            Some("target_rejected: HTTP 403: forbidden")
        );
    }

    #[test]
    fn attempt_failure_code_unrecognized() {
        let attempt =
            RotationAttempt::try_from(attempt_response(Some("from_the_future: detail"))).unwrap();
        assert_eq!(attempt.failure_code, Some(RotationFailureCode::Unknown));
    }

    #[test]
    fn attempt_failure_code_none_without_reason() {
        let attempt = RotationAttempt::try_from(attempt_response(None)).unwrap();
        assert_eq!(attempt.failure_code, None);
    }
}
