use std::sync::Arc;

use bitwarden_api_api::models::{
    CreateRotationConfigRequestModel, PamRotationConfigDetailResponseModel,
    PamRotationConfigResponseModel, UpdateRotationConfigRequestModel,
};
use bitwarden_core::{FromClient, OrganizationId, client::ApiConfigurations, require};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    actions::{RotationConfigActions, rotation_config_actions},
    error::RotationError,
    models::{RotationJob, TargetSystemMethod, TargetSystemStatus},
    validate::{validate_config_create, validate_config_update},
};
use crate::{RotationConfigId, TargetSystemId};

/// A managed credential: the link between a vault cipher and the target system its credential is
/// rotated against.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfig {
    /// The config's unique identifier.
    pub id: RotationConfigId,
    /// The organization this config belongs to.
    pub organization_id: OrganizationId,
    /// The vault cipher whose credential this config manages.
    ///
    /// Only the id is here. The cipher's name is vault data and has to be decrypted from the
    /// caller's own cipher state - the rotation endpoints never carry it.
    pub cipher_id: CipherId,
    /// The target system credentials are rotated against.
    pub target_system_id: TargetSystemId,
    /// The target system's display name as of the config's last write.
    ///
    /// Denormalized by the server, so it can lag a rename. Prefer the name from the target system
    /// itself when it has been loaded, and treat this as the fallback.
    pub target_system_name: String,
    /// The target system's rotation method as of the config's last write. Denormalized, and the
    /// field that decides which actions the config offers.
    pub target_system_method: TargetSystemMethod,
    /// The account within the target system - a username, UPN, or service-account name.
    pub account_identity: String,
    /// Whether the connector terminates the account's sessions after a successful rotation.
    pub terminate_sessions: bool,
    /// The Quartz cron expression driving scheduled rotation, or `None` for no schedule.
    pub schedule_cron: Option<String>,
    /// Whether the credential is rotated when an access lease over the cipher ends.
    pub rotate_on_access_end: bool,
    /// When false, no new rotation jobs are dispatched. Jobs in flight run to completion.
    pub enabled: bool,
    /// The most recent completed rotation (UTC), or `None` if it has never rotated.
    pub last_rotation_at: Option<DateTime<Utc>>,
    /// The next scheduled rotation (UTC). `None` when there is no schedule or the config is
    /// paused.
    pub next_rotation_at: Option<DateTime<Utc>>,
    /// Whether a job is currently pending or claimed for this config.
    pub has_active_job: bool,
    /// Whether a manual-method config is waiting for an operator to record an out-of-band
    /// rotation.
    pub awaiting_manual_rotation: bool,
    /// When the config was created (UTC).
    pub creation_date: DateTime<Utc>,
    /// When the config was last modified (UTC).
    pub revision_date: DateTime<Utc>,
}

impl RotationConfig {
    /// Which actions this config offers, given the status of its target system.
    ///
    /// See [`rotation_config_actions`] for how `target_status` is treated when the target system
    /// has not been loaded.
    pub fn actions(&self, target_status: Option<TargetSystemStatus>) -> RotationConfigActions {
        rotation_config_actions(self, target_status)
    }
}

impl TryFrom<PamRotationConfigResponseModel> for RotationConfig {
    type Error = RotationError;

    fn try_from(response: PamRotationConfigResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: RotationConfigId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            target_system_id: TargetSystemId::new(require!(response.target_system_id)),
            target_system_name: response.target_system_name.unwrap_or_default(),
            target_system_method: require!(response.target_system_method).into(),
            account_identity: require!(response.account_identity),
            terminate_sessions: response.terminate_sessions.unwrap_or(false),
            schedule_cron: response.schedule_cron,
            rotate_on_access_end: response.rotate_on_access_end.unwrap_or(false),
            // The server omits `enabled` on an active config rather than sending `true`.
            enabled: response.enabled.unwrap_or(true),
            last_rotation_at: response
                .last_rotation_at
                .map(|date| date.parse())
                .transpose()?,
            next_rotation_at: response
                .next_rotation_at
                .map(|date| date.parse())
                .transpose()?,
            has_active_job: response.has_active_job.unwrap_or(false),
            awaiting_manual_rotation: response.awaiting_manual_rotation.unwrap_or(false),
            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}

/// A config together with its rotation history.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfigDetail {
    /// The config itself.
    #[serde(flatten)]
    pub config: RotationConfig,
    /// The config's rotation jobs, newest first, each carrying its attempts oldest first.
    pub jobs: Vec<RotationJob>,
}

impl TryFrom<PamRotationConfigDetailResponseModel> for RotationConfigDetail {
    type Error = RotationError;

    fn try_from(response: PamRotationConfigDetailResponseModel) -> Result<Self, Self::Error> {
        let jobs = response
            .jobs
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(RotationJob::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        // The server flattens the config's own fields onto the detail payload, so the list model is
        // rebuilt from the same object rather than a nested one.
        let config = RotationConfig::try_from(PamRotationConfigResponseModel {
            object: response.object,
            id: response.id,
            organization_id: response.organization_id,
            cipher_id: response.cipher_id,
            target_system_id: response.target_system_id,
            target_system_name: response.target_system_name,
            target_system_method: response.target_system_method,
            account_identity: response.account_identity,
            terminate_sessions: response.terminate_sessions,
            schedule_cron: response.schedule_cron,
            rotate_on_access_end: response.rotate_on_access_end,
            next_rotation_at: response.next_rotation_at,
            enabled: response.enabled,
            last_rotation_at: response.last_rotation_at,
            has_active_job: response.has_active_job,
            awaiting_manual_rotation: response.awaiting_manual_rotation,
            creation_date: response.creation_date,
            revision_date: response.revision_date,
        })?;

        Ok(Self { config, jobs })
    }
}

/// Request to create a rotation config.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfigCreateRequest {
    /// The vault cipher whose credential this config will manage.
    pub cipher_id: CipherId,
    /// The target system to rotate against.
    pub target_system_id: TargetSystemId,
    /// The account within the target system.
    pub account_identity: String,
    /// Whether to terminate the account's sessions after a successful rotation.
    pub terminate_sessions: bool,
    /// A Quartz cron expression, or `None` for no scheduled rotation.
    pub schedule_cron: Option<String>,
    /// Whether to rotate when an access lease over the cipher ends.
    pub rotate_on_access_end: bool,
}

impl From<RotationConfigCreateRequest> for CreateRotationConfigRequestModel {
    fn from(request: RotationConfigCreateRequest) -> Self {
        Self {
            cipher_id: request.cipher_id.into(),
            target_system_id: request.target_system_id.into(),
            account_identity: request.account_identity,
            terminate_sessions: Some(request.terminate_sessions),
            schedule_cron: request.schedule_cron,
            rotate_on_access_end: Some(request.rotate_on_access_end),
        }
    }
}

/// Request to update a rotation config.
///
/// The account identity and the schedule travel together because the server takes them in one
/// `PUT`, so a caller changing only the schedule still sends the current account identity. Note
/// that the server locks the account identity while a job is in flight - see
/// [`RotationConfigActions::mutations_locked`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfigUpdateRequest {
    /// The account within the target system.
    pub account_identity: String,
    /// Whether to terminate the account's sessions after a successful rotation.
    pub terminate_sessions: bool,
    /// A Quartz cron expression, or `None` for no scheduled rotation.
    pub schedule_cron: Option<String>,
    /// Whether to rotate when an access lease over the cipher ends.
    pub rotate_on_access_end: bool,
}

impl From<RotationConfigUpdateRequest> for UpdateRotationConfigRequestModel {
    fn from(request: RotationConfigUpdateRequest) -> Self {
        Self {
            account_identity: request.account_identity,
            terminate_sessions: Some(request.terminate_sessions),
            schedule_cron: request.schedule_cron,
            rotate_on_access_end: Some(request.rotate_on_access_end),
        }
    }
}

/// Client for PAM managed-credential (rotation config) operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct RotationConfigsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RotationConfigsClient {
    /// Lists the organization's rotation configs.
    pub async fn list(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<RotationConfig>, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .get_all(organization_id.into())
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(RotationConfig::try_from)
            .collect()
    }

    /// Reads one config with its rotation history.
    pub async fn get(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<RotationConfigDetail, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .get(organization_id.into(), id.into())
            .await?;

        RotationConfigDetail::try_from(response)
    }

    /// Validates and creates a rotation config.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        request: RotationConfigCreateRequest,
    ) -> Result<RotationConfigDetail, RotationError> {
        validate_config_create(&request)?;

        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .post(organization_id.into(), request.into())
            .await?;

        RotationConfigDetail::try_from(response)
    }

    /// Validates and updates a rotation config's account and schedule.
    pub async fn update(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
        request: RotationConfigUpdateRequest,
    ) -> Result<RotationConfigDetail, RotationError> {
        validate_config_update(&request)?;

        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .put(organization_id.into(), id.into(), request.into())
            .await?;

        RotationConfigDetail::try_from(response)
    }

    /// Pauses a config, so no new rotation jobs are dispatched.
    pub async fn pause(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .pause(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Resumes a paused config.
    pub async fn resume(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .resume(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Dispatches an on-demand rotation now, subject to the server's per-config cooldown.
    pub async fn rotate_now(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .rotate(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Records that an operator rotated a manual-target config's credential out of band, clearing
    /// its awaiting-manual-rotation state.
    pub async fn record_manual_rotation(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .record_manual(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Deletes a rotation config. The cipher and the target system are untouched; only the link
    /// between them, and its rotation history, go away.
    pub async fn delete(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .delete(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Which actions a config offers, given the status of its target system.
    ///
    /// Exposed on the client so non-Rust callers can reach the same predicates the Rust API has on
    /// [`RotationConfig::actions`] - a tsify struct crosses the WASM boundary as plain data and
    /// leaves its methods behind. All five flags are derived in one call because they are not
    /// independent; see [`RotationConfigActions`].
    pub fn actions(
        &self,
        config: RotationConfig,
        target_status: Option<TargetSystemStatus>,
    ) -> RotationConfigActions {
        config.actions(target_status)
    }
}
