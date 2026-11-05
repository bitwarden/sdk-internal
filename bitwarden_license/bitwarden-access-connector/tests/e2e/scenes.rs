//! Seeder scenes and queries for the PAM entities, matching the server's wire contract: camelCase
//! JSON, enums as integers, optional arguments omitted when `None`.

use bitwarden_test::play::{Query, SceneTemplate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Integer values of the server's PAM enums.
pub mod enums {
    /// `PamAccessConnectorStatus`.
    pub mod connector_status {
        pub const ENABLED: i32 = 0;
        pub const DISABLED: i32 = 1;
    }

    /// `PamTargetSystemMethod`.
    pub mod target_method {
        pub const AUTOMATIC: i32 = 0;
        pub const MANUAL: i32 = 1;
    }

    /// `PamTargetSystemStatus`.
    pub mod target_status {
        pub const ACTIVE: i32 = 0;
        pub const DISABLED: i32 = 1;
        pub const PENDING_SEAL: i32 = 2;
    }

    /// `PamRotationJobAction`.
    pub mod job_action {
        pub const NONE: i32 = 0;
        pub const CLAIMED: i32 = 1;
        pub const SUCCEEDED: i32 = 2;
        pub const FAILED: i32 = 3;
    }

    /// `PamRotationAttemptAction`.
    pub mod attempt_action {
        pub const NONE: i32 = 0;
        pub const ROTATED: i32 = 1;
        pub const ERRORED: i32 = 2;
    }

    /// `PamRotationSyncState`.
    pub mod sync_state {
        pub const TARGET_UNCHANGED: i32 = 0;
        pub const TARGET_UPDATED: i32 = 1;
        pub const INDETERMINATE: i32 = 2;
    }

    /// `PamSessionTerminationOutcome`.
    pub mod session_termination {
        pub const NOT_REQUESTED: i32 = 0;
        pub const TERMINATED: i32 = 1;
        pub const TERM_FAILED: i32 = 2;
    }
}

/// Arguments for [`OrganizationAccessConnectorScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationAccessConnectorArgs {
    pub organization_id: Uuid,
    pub name: String,
    /// `AccessTokenSecrets::encrypted_payload`.
    pub encrypted_payload: String,
    /// `AccessTokenSecrets::key`.
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationAccessConnectorResult {
    pub access_connector_id: Uuid,
    pub api_key_id: Uuid,
    pub client_secret: String,
}

/// Registers an access connector and the API key behind its token.
pub struct OrganizationAccessConnectorScene;

impl SceneTemplate for OrganizationAccessConnectorScene {
    type Arguments = OrganizationAccessConnectorArgs;
    type Result = OrganizationAccessConnectorResult;

    fn template_name() -> &'static str {
        "OrganizationAccessConnectorScene"
    }
}

/// Arguments for [`PamTargetSystemScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamTargetSystemArgs {
    pub organization_id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamTargetSystemResult {
    pub target_system_id: Uuid,
}

/// Creates a target system in `PendingSeal`.
pub struct PamTargetSystemScene;

impl SceneTemplate for PamTargetSystemScene {
    type Arguments = PamTargetSystemArgs;
    type Result = PamTargetSystemResult;

    fn template_name() -> &'static str {
        "PamTargetSystemScene"
    }
}

/// Arguments for [`PamTargetSystemSealScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamTargetSystemSealArgs {
    pub target_system_id: Uuid,
    pub sealed_data: String,
    pub wrapped_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
}

/// Sets a target system's sealed blob and status. Re-run it with a `status` to change that later.
pub struct PamTargetSystemSealScene;

impl SceneTemplate for PamTargetSystemSealScene {
    type Arguments = PamTargetSystemSealArgs;
    type Result = PamTargetSystemResult;

    fn template_name() -> &'static str {
        "PamTargetSystemSealScene"
    }
}

/// Arguments for [`PamAccessConnectorTargetAssignmentScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamAccessConnectorTargetAssignmentArgs {
    pub organization_id: Uuid,
    pub access_connector_id: Uuid,
    pub target_system_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamAccessConnectorTargetAssignmentResult {
    pub assignment_id: Uuid,
}

/// Assigns a connector to a target system.
pub struct PamAccessConnectorTargetAssignmentScene;

impl SceneTemplate for PamAccessConnectorTargetAssignmentScene {
    type Arguments = PamAccessConnectorTargetAssignmentArgs;
    type Result = PamAccessConnectorTargetAssignmentResult;

    fn template_name() -> &'static str {
        "PamAccessConnectorTargetAssignmentScene"
    }
}

/// Arguments for [`PamRotationConfigScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationConfigArgs {
    pub organization_id: Uuid,
    pub cipher_id: Uuid,
    pub target_system_id: Uuid,
    pub sealed_data: String,
    pub wrapped_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationConfigResult {
    pub rotation_config_id: Uuid,
}

/// Creates a rotation config that the sweep never schedules on its own.
pub struct PamRotationConfigScene;

impl SceneTemplate for PamRotationConfigScene {
    type Arguments = PamRotationConfigArgs;
    type Result = PamRotationConfigResult;

    fn template_name() -> &'static str {
        "PamRotationConfigScene"
    }
}

/// Arguments for [`PamRotationConfigUpdateScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationConfigUpdateArgs {
    pub rotation_config_id: Uuid,
    pub enabled: bool,
}

/// Enables or disables a rotation config.
pub struct PamRotationConfigUpdateScene;

impl SceneTemplate for PamRotationConfigUpdateScene {
    type Arguments = PamRotationConfigUpdateArgs;
    type Result = PamRotationConfigResult;

    fn template_name() -> &'static str {
        "PamRotationConfigUpdateScene"
    }
}

/// Arguments for [`PamRotationJobScene`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationJobArgs {
    pub rotation_config_id: Uuid,
    /// Negative values seed an already expired job.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_claimable_in_seconds: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationJobResult {
    pub job_id: Uuid,
}

/// Creates an unclaimed on-demand rotation job.
pub struct PamRotationJobScene;

impl SceneTemplate for PamRotationJobScene {
    type Arguments = PamRotationJobArgs;
    type Result = PamRotationJobResult;

    fn template_name() -> &'static str {
        "PamRotationJobScene"
    }
}

/// Arguments for [`PamRotationJobStateQuery`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationJobStateArgs {
    pub job_id: Uuid,
}

/// A rotation job and its attempts, as the server stores them.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationJobState {
    pub job_id: Uuid,
    pub action: i32,
    /// Only set while the job is `Claimed`; use the attempts to see who claimed it afterwards.
    pub claimed_by_access_connector_id: Option<Uuid>,
    /// The rotation config's last rotation date.
    pub last_rotation_date: Option<String>,
    /// Ordered by creation date.
    pub attempts: Vec<PamRotationAttemptState>,
}

/// One claim of a job by a connector.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamRotationAttemptState {
    pub attempt_id: Uuid,
    pub claimed_by_access_connector_id: Uuid,
    pub action: i32,
    pub cipher_updated: bool,
    pub failure_reason: Option<String>,
    pub sync_state: Option<i32>,
    pub session_termination: Option<i32>,
    pub resolved_date: Option<String>,
}

pub struct PamRotationJobStateQuery {
    args: PamRotationJobStateArgs,
    pub state: PamRotationJobState,
}

impl Query for PamRotationJobStateQuery {
    type Args = PamRotationJobStateArgs;
    type Result = PamRotationJobState;

    fn template_name() -> &'static str {
        "PamRotationJobStateQuery"
    }

    fn args(&self) -> &Self::Args {
        &self.args
    }

    fn from_result(result: Self::Result) -> Self {
        Self {
            args: PamRotationJobStateArgs {
                job_id: result.job_id,
            },
            state: result,
        }
    }
}

/// Arguments for [`PamAccessConnectorStateQuery`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PamAccessConnectorStateArgs {
    pub access_connector_id: Uuid,
}

/// A connector's status and last heartbeat.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamAccessConnectorState {
    pub access_connector_id: Uuid,
    pub status: i32,
    pub last_heartbeat_date: Option<String>,
}

pub struct PamAccessConnectorStateQuery {
    args: PamAccessConnectorStateArgs,
    pub state: PamAccessConnectorState,
}

impl Query for PamAccessConnectorStateQuery {
    type Args = PamAccessConnectorStateArgs;
    type Result = PamAccessConnectorState;

    fn template_name() -> &'static str {
        "PamAccessConnectorStateQuery"
    }

    fn args(&self) -> &Self::Args {
        &self.args
    }

    fn from_result(result: Self::Result) -> Self {
        Self {
            args: PamAccessConnectorStateArgs {
                access_connector_id: result.access_connector_id,
            },
            state: result,
        }
    }
}

/// Arguments for [`OrganizationCipherQuery`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCipherArgs {
    pub cipher_id: Uuid,
}

/// A cipher row as stored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCipherRow {
    pub cipher_id: Uuid,
    pub r#type: i32,
    /// The raw `Cipher.Data` JSON string.
    pub data: String,
    /// The item key, an EncString under the organization key.
    pub key: Option<String>,
    pub revision_date: String,
}

pub struct OrganizationCipherQuery {
    args: OrganizationCipherArgs,
    pub row: OrganizationCipherRow,
}

impl Query for OrganizationCipherQuery {
    type Args = OrganizationCipherArgs;
    type Result = OrganizationCipherRow;

    fn template_name() -> &'static str {
        "OrganizationCipherQuery"
    }

    fn args(&self) -> &Self::Args {
        &self.args
    }

    fn from_result(result: Self::Result) -> Self {
        Self {
            args: OrganizationCipherArgs {
                cipher_id: result.cipher_id,
            },
            row: result,
        }
    }
}
