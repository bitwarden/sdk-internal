use bitwarden_api_api::models::{
    PamAccessConnectorStatus as ApiAccessConnectorStatus, PamPasswordPolicyRequestModel,
    PamPasswordPolicyResponseModel, PamRotationAttemptResponseModel,
    PamRotationAttemptStatus as ApiRotationAttemptStatus, PamRotationJobResponseModel,
    PamRotationJobStatus as ApiRotationJobStatus, PamRotationSource as ApiRotationSource,
    PamRotationSyncState as ApiRotationSyncState,
    PamSessionTerminationOutcome as ApiSessionTerminationOutcome,
    PamTargetSystemKind as ApiTargetSystemKind, PamTargetSystemMethod as ApiTargetSystemMethod,
    PamTargetSystemStatus as ApiTargetSystemStatus,
};
use bitwarden_core::require;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::error::RotationError;
use crate::{AccessConnectorId, RotationAttemptId, RotationConfigId, RotationJobId};

/// Lifecycle state of an access connector.
///
/// [`Disabled`](AccessConnectorStatus::Disabled) is **reversible**: re-enabling flips it back to
/// [`Enabled`](AccessConnectorStatus::Enabled). Removing a connector entirely - which invalidates
/// its credential - is a delete, not a disable. Because a connector holds the plaintext
/// organization key, rotating the organization key remains the remediation for a suspected
/// compromise.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum AccessConnectorStatus {
    /// The connector may authenticate and claim rotation jobs.
    Enabled,
    /// The connector cannot claim new jobs and its running jobs are released. Its credential is
    /// retained so it can be re-enabled.
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
            // A caller cannot ask the server to store a method this SDK could not name in the
            // first place; sending `__Unknown` would serialize a meaningless tinyint.
            TargetSystemMethod::Unknown => Err(RotationError::UnrecognizedVariant),
        }
    }
}

/// The technology a target system represents. Only meaningful when the target system's method is
/// [`Automatic`](TargetSystemMethod::Automatic) - a manual rotation has no integration.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum TargetSystemKind {
    /// Entra ID / Azure AD service-account password rotation.
    Entra,
    /// SQL Server login password rotation.
    Mssql,
    /// An operator-supplied script run by the connector.
    CustomScript,
    /// On-premises Active Directory account password rotation. Distinct from
    /// [`Entra`](TargetSystemKind::Entra), which is Entra ID / Azure AD.
    ActiveDirectory,
    /// A kind this SDK version does not recognize.
    Unknown,
}

impl From<ApiTargetSystemKind> for TargetSystemKind {
    /// # Interim handling of Active Directory
    ///
    /// The server does not yet publish `PamTargetSystemKind.ActiveDirectory = 3` in its OpenAPI
    /// document, so the generated enum has no named variant for it and wire value `3` arrives
    /// through the generator's forward-compatibility catch-all as `__Unknown(3)`.
    ///
    /// Recognizing it here rather than hand-adding a variant to `bitwarden-api-api` keeps the
    /// workaround in the crate that owns this boundary: `support/generate-api-bindings-ci.sh`
    /// deletes the generated crate's `src` before regenerating, so an edit there does not survive.
    ///
    /// Once the server publishes the value, regenerating the bindings produces
    /// `PamTargetSystemKind::ActiveDirectory`, and the two `__Unknown(3)` arms - the one below and
    /// its outbound counterpart in `TryFrom<TargetSystemKind> for ApiTargetSystemKind` - are
    /// replaced by matches on that variant. Those two arms are the only sites to change.
    fn from(kind: ApiTargetSystemKind) -> Self {
        match kind {
            ApiTargetSystemKind::Entra => Self::Entra,
            ApiTargetSystemKind::Mssql => Self::Mssql,
            ApiTargetSystemKind::CustomScript => Self::CustomScript,
            ApiTargetSystemKind::__Unknown(3) => Self::ActiveDirectory,
            ApiTargetSystemKind::__Unknown(_) => Self::Unknown,
        }
    }
}

impl TryFrom<TargetSystemKind> for ApiTargetSystemKind {
    type Error = RotationError;

    fn try_from(kind: TargetSystemKind) -> Result<Self, Self::Error> {
        match kind {
            TargetSystemKind::Entra => Ok(Self::Entra),
            TargetSystemKind::Mssql => Ok(Self::Mssql),
            TargetSystemKind::CustomScript => Ok(Self::CustomScript),
            // Interim, per the inbound conversion above: `__Unknown(3)` serializes through
            // `as_i64()` to the same `3` a named variant would.
            TargetSystemKind::ActiveDirectory => Ok(Self::__Unknown(3)),
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
    /// A status this SDK version does not recognize.
    Unknown,
}

impl From<ApiTargetSystemStatus> for TargetSystemStatus {
    fn from(status: ApiTargetSystemStatus) -> Self {
        match status {
            ApiTargetSystemStatus::Active => Self::Active,
            ApiTargetSystemStatus::Disabled => Self::Disabled,
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
    /// Queued, not yet claimed by a connector.
    Pending,
    /// A connector is executing the job.
    Claimed,
    /// Every attempt succeeded and the vault cipher has been updated.
    Succeeded,
    /// The job exhausted its retry budget.
    Failed,
    /// The connector did not report back within the deadline.
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
    /// The target system accepted the new credential.
    Rotated,
    /// The attempt failed; see [`RotationAttempt::failure_reason`].
    Errored,
    /// The attempt was abandoned, for example because the connector was revoked mid-job.
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

/// Whether the target system ended up holding the rotated credential.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum RotationSyncState {
    /// The target system was not modified, so no vault write was attempted.
    TargetUnchanged,
    /// The target system accepted the new credential and the vault cipher was updated.
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

/// Password generation policy for a target system.
///
/// For [`Automatic`](TargetSystemMethod::Automatic) systems the connector generates the new
/// credential under these constraints. For [`Manual`](TargetSystemMethod::Manual) systems they are
/// the rules the operator is expected to follow when rotating by hand - nothing enforces them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    /// Minimum length of a generated credential.
    pub min_length: i32,
    /// Maximum length of a generated credential.
    pub max_length: i32,
    /// Whether generated credentials may include `A-Z`.
    pub include_uppercase: bool,
    /// Whether generated credentials may include `a-z`.
    pub include_lowercase: bool,
    /// Whether generated credentials may include `0-9`.
    pub include_digits: bool,
    /// Whether generated credentials may include punctuation.
    pub include_symbols: bool,
}

impl From<PamPasswordPolicyResponseModel> for PasswordPolicy {
    fn from(policy: PamPasswordPolicyResponseModel) -> Self {
        Self {
            min_length: policy.min_length.unwrap_or_default(),
            max_length: policy.max_length.unwrap_or_default(),
            include_uppercase: policy.include_uppercase.unwrap_or(false),
            include_lowercase: policy.include_lowercase.unwrap_or(false),
            include_digits: policy.include_digits.unwrap_or(false),
            include_symbols: policy.include_symbols.unwrap_or(false),
        }
    }
}

impl From<PasswordPolicy> for PamPasswordPolicyRequestModel {
    fn from(policy: PasswordPolicy) -> Self {
        Self {
            min_length: policy.min_length,
            max_length: policy.max_length,
            include_uppercase: Some(policy.include_uppercase),
            include_lowercase: Some(policy.include_lowercase),
            include_digits: Some(policy.include_digits),
            include_symbols: Some(policy.include_symbols),
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
    /// Operator-facing failure reason, set when the attempt errored or was abandoned.
    ///
    /// Server-authored text describing the *failure*, never the credential - safe to render, but
    /// it originates off-client, so treat it as untrusted for anything beyond display.
    pub failure_reason: Option<String>,
    /// Whether the vault cipher was written with the rotated credential.
    pub cipher_updated: bool,
    /// Whether the target system ended up holding the rotated credential. `None` until the
    /// attempt resolves.
    pub sync_state: Option<RotationSyncState>,
    /// Whether active sessions were terminated after rotating. `None` until the attempt resolves.
    pub session_termination: Option<SessionTerminationOutcome>,
    /// When the connector began this attempt (UTC).
    pub started_at: DateTime<Utc>,
    /// When the attempt resolved (UTC), or `None` while it is still executing.
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

/// One dispatch of the rotation workflow for a config.
///
/// A job may carry several attempts - retries, or several assigned connectors racing to claim it.
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
    /// The connector holding the job, when one has claimed it.
    pub claimed_by_access_connector_id: Option<AccessConnectorId>,
    /// When the job was claimed (UTC), or `None` while it is still pending.
    pub claimed_at: Option<DateTime<Utc>>,
    /// When the job was queued (UTC).
    pub created_at: DateTime<Utc>,
    /// The earliest a connector may claim this job again after a released or failed attempt (UTC).
    pub next_claimable_at: Option<DateTime<Utc>>,
    /// When the job's claim deadline lapses (UTC), after which it is considered timed out.
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

    #[test]
    fn every_named_kind_round_trips_through_its_wire_value() {
        for (kind, wire) in [
            (TargetSystemKind::Entra, 0),
            (TargetSystemKind::Mssql, 1),
            (TargetSystemKind::CustomScript, 2),
            (TargetSystemKind::ActiveDirectory, 3),
        ] {
            let sent = ApiTargetSystemKind::try_from(kind).expect("a named kind is representable");

            assert_eq!(sent.as_i64(), wire);
            assert_eq!(
                TargetSystemKind::from(ApiTargetSystemKind::from_i64(wire)),
                kind
            );
        }
    }

    /// The forward-compatibility guarantee from the module docs: a kind only a newer server knows
    /// degrades rather than failing the payload it arrived in, and cannot be written back out.
    #[test]
    fn a_kind_this_version_does_not_model_degrades_to_unknown() {
        assert_eq!(
            TargetSystemKind::from(ApiTargetSystemKind::from_i64(4)),
            TargetSystemKind::Unknown
        );
        assert!(matches!(
            ApiTargetSystemKind::try_from(TargetSystemKind::Unknown),
            Err(RotationError::UnrecognizedVariant)
        ));
    }

    /// These strings are the TypeScript union the clients build their kind list against, so a
    /// rename here breaks that list at compile time rather than anywhere visible from Rust.
    #[test]
    fn kinds_serialize_to_the_snake_case_names_typescript_sees() {
        for (kind, name) in [
            (TargetSystemKind::Entra, "entra"),
            (TargetSystemKind::Mssql, "mssql"),
            (TargetSystemKind::CustomScript, "custom_script"),
            (TargetSystemKind::ActiveDirectory, "active_directory"),
            (TargetSystemKind::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(kind).expect("it serializes"), name);
            assert_eq!(
                serde_json::from_value::<TargetSystemKind>(name.into()).expect("it deserializes"),
                kind
            );
        }
    }
}
