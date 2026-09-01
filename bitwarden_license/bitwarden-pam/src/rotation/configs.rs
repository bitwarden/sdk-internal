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

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            PamRotationConfigResponseModelListResponseModel, PamRotationJobResponseModel,
            PamRotationJobStatus as ApiRotationJobStatus, PamRotationSource as ApiRotationSource,
            PamTargetSystemMethod as ApiTargetSystemMethod,
        },
    };
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::rotation::{
        models::{RotationJobStatus, RotationSource},
        validate::RotationValidationError,
    };

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn config_id() -> RotationConfigId {
        RotationConfigId::new(uuid!("22222222-2222-2222-2222-222222222222"))
    }

    fn cipher_id() -> CipherId {
        CipherId::new(uuid!("33333333-3333-3333-3333-333333333333"))
    }

    fn target_system_id() -> TargetSystemId {
        TargetSystemId::new(uuid!("44444444-4444-4444-4444-444444444444"))
    }

    fn job_id() -> Uuid {
        uuid!("55555555-5555-5555-5555-555555555555")
    }

    fn client(api_client: ApiClient) -> RotationConfigsClient {
        RotationConfigsClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    /// A payload with every optional field populated, so a test that clears one is unambiguous
    /// about which field it is exercising.
    fn sample_response() -> PamRotationConfigResponseModel {
        PamRotationConfigResponseModel {
            id: Some(config_id().into()),
            organization_id: Some(organization_id().into()),
            cipher_id: Some(cipher_id().into()),
            target_system_id: Some(target_system_id().into()),
            target_system_name: Some("Prod SQL".to_string()),
            target_system_method: Some(ApiTargetSystemMethod::Automatic),
            account_identity: Some("svc_rotation".to_string()),
            terminate_sessions: Some(true),
            schedule_cron: Some("0 0 0 * * ?".to_string()),
            rotate_on_access_end: Some(true),
            next_rotation_at: Some("2026-02-02T00:00:00Z".to_string()),
            enabled: Some(true),
            last_rotation_at: Some("2026-02-01T00:00:00Z".to_string()),
            has_active_job: Some(true),
            awaiting_manual_rotation: Some(true),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            revision_date: Some("2026-01-15T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    /// The same config as [`sample_response`], as the detail routes return it: the config's own
    /// fields flattened onto the payload, plus its rotation history.
    fn sample_detail_response(
        jobs: Option<Vec<PamRotationJobResponseModel>>,
    ) -> PamRotationConfigDetailResponseModel {
        let config = sample_response();
        PamRotationConfigDetailResponseModel {
            object: config.object,
            id: config.id,
            organization_id: config.organization_id,
            cipher_id: config.cipher_id,
            target_system_id: config.target_system_id,
            target_system_name: config.target_system_name,
            target_system_method: config.target_system_method,
            account_identity: config.account_identity,
            terminate_sessions: config.terminate_sessions,
            schedule_cron: config.schedule_cron,
            rotate_on_access_end: config.rotate_on_access_end,
            next_rotation_at: config.next_rotation_at,
            enabled: config.enabled,
            last_rotation_at: config.last_rotation_at,
            has_active_job: config.has_active_job,
            awaiting_manual_rotation: config.awaiting_manual_rotation,
            creation_date: config.creation_date,
            revision_date: config.revision_date,
            jobs,
        }
    }

    fn sample_job(id: Uuid) -> PamRotationJobResponseModel {
        PamRotationJobResponseModel {
            id: Some(id),
            rotation_config_id: Some(config_id().into()),
            source: Some(ApiRotationSource::OnDemand),
            status: Some(ApiRotationJobStatus::Pending),
            creation_date: Some("2026-01-10T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn create_request() -> RotationConfigCreateRequest {
        RotationConfigCreateRequest {
            cipher_id: cipher_id(),
            target_system_id: target_system_id(),
            account_identity: "svc_rotation".to_string(),
            terminate_sessions: true,
            schedule_cron: Some("0 0 0 * * ?".to_string()),
            rotate_on_access_end: true,
        }
    }

    fn update_request() -> RotationConfigUpdateRequest {
        RotationConfigUpdateRequest {
            account_identity: "svc_rotation".to_string(),
            terminate_sessions: true,
            schedule_cron: Some("0 0 0 * * ?".to_string()),
            rotate_on_access_end: true,
        }
    }

    #[test]
    fn a_full_payload_maps_every_field() {
        let config = RotationConfig::try_from(sample_response()).expect("the payload is valid");

        assert_eq!(config.id, config_id());
        assert_eq!(config.organization_id, organization_id());
        assert_eq!(config.cipher_id, cipher_id());
        assert_eq!(config.target_system_id, target_system_id());
        assert_eq!(config.target_system_name, "Prod SQL");
        assert_eq!(config.target_system_method, TargetSystemMethod::Automatic);
        assert_eq!(config.account_identity, "svc_rotation");
        assert!(config.terminate_sessions);
        assert_eq!(config.schedule_cron.as_deref(), Some("0 0 0 * * ?"));
        assert!(config.rotate_on_access_end);
        assert!(config.enabled);
        assert_eq!(
            config.last_rotation_at,
            Some("2026-02-01T00:00:00Z".parse().expect("a valid timestamp"))
        );
        assert_eq!(
            config.next_rotation_at,
            Some("2026-02-02T00:00:00Z".parse().expect("a valid timestamp"))
        );
        assert!(config.has_active_job);
        assert!(config.awaiting_manual_rotation);
        assert_eq!(
            config.creation_date,
            "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            config.revision_date,
            "2026-01-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    /// The one inverted default on this payload: the server omits `enabled` on an active config
    /// rather than sending `true`. Defaulting it to `false` like the other flags would render every
    /// running config as paused, and offer resume instead of pause.
    #[test]
    fn an_omitted_enabled_flag_means_the_config_is_active() {
        let config = RotationConfig::try_from(PamRotationConfigResponseModel {
            enabled: None,
            ..sample_response()
        })
        .expect("the payload is valid");

        assert!(config.enabled);
        assert!(config.actions(Some(TargetSystemStatus::Active)).can_pause);
        assert!(!config.actions(Some(TargetSystemStatus::Active)).can_resume);
    }

    /// Every other flag defaults the other way: absent means *not* set. A config the server has
    /// never rotated has no timestamps, and an unnamed target reads as empty rather than failing.
    #[test]
    fn the_remaining_absent_fields_default_to_not_set() {
        let config = RotationConfig::try_from(PamRotationConfigResponseModel {
            target_system_name: None,
            terminate_sessions: None,
            schedule_cron: None,
            rotate_on_access_end: None,
            last_rotation_at: None,
            next_rotation_at: None,
            has_active_job: None,
            awaiting_manual_rotation: None,
            ..sample_response()
        })
        .expect("the payload is valid");

        assert_eq!(config.target_system_name, "");
        assert!(!config.terminate_sessions);
        assert_eq!(config.schedule_cron, None);
        assert!(!config.rotate_on_access_end);
        assert_eq!(config.last_rotation_at, None);
        assert_eq!(config.next_rotation_at, None);
        assert!(!config.has_active_job);
        assert!(!config.awaiting_manual_rotation);
    }

    #[test]
    fn a_missing_required_field_is_reported_rather_than_defaulted() {
        for response in [
            PamRotationConfigResponseModel {
                id: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                organization_id: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                cipher_id: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                target_system_id: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                target_system_method: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                account_identity: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                creation_date: None,
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                revision_date: None,
                ..sample_response()
            },
        ] {
            assert!(matches!(
                RotationConfig::try_from(response),
                Err(RotationError::MissingField(_))
            ));
        }
    }

    #[test]
    fn an_unparseable_date_is_reported() {
        for response in [
            PamRotationConfigResponseModel {
                creation_date: Some("not a date".to_string()),
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                revision_date: Some("not a date".to_string()),
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                last_rotation_at: Some("not a date".to_string()),
                ..sample_response()
            },
            PamRotationConfigResponseModel {
                next_rotation_at: Some("not a date".to_string()),
                ..sample_response()
            },
        ] {
            assert!(matches!(
                RotationConfig::try_from(response),
                Err(RotationError::Chrono(_))
            ));
        }
    }

    #[test]
    fn an_unrecognized_method_degrades_to_unknown() {
        let config = RotationConfig::try_from(PamRotationConfigResponseModel {
            target_system_method: Some(ApiTargetSystemMethod::__Unknown(9)),
            ..sample_response()
        })
        .expect("an unknown method still maps");

        assert_eq!(config.target_system_method, TargetSystemMethod::Unknown);
    }

    /// The detail conversion hand-copies the config's eighteen fields out of the flattened payload,
    /// so a field dropped there would silently read as absent - and for `enabled` that would flip
    /// an active config to paused. Comparing against the list conversion of the same config pins
    /// all eighteen at once.
    #[test]
    fn the_detail_payload_yields_the_same_config_as_the_list_payload() {
        let detail = RotationConfigDetail::try_from(sample_detail_response(Some(vec![
            sample_job(job_id()),
        ])))
        .expect("the payload is valid");

        assert_eq!(
            detail.config,
            RotationConfig::try_from(sample_response()).expect("the payload is valid")
        );
    }

    #[test]
    fn detail_jobs_keep_the_order_the_server_sent() {
        let second = uuid!("66666666-6666-6666-6666-666666666666");
        let detail = RotationConfigDetail::try_from(sample_detail_response(Some(vec![
            sample_job(job_id()),
            sample_job(second),
        ])))
        .expect("the payload is valid");

        let ids: Vec<Uuid> = detail.jobs.iter().map(|job| job.id.into()).collect();
        assert_eq!(ids, [job_id(), second]);
        assert_eq!(detail.jobs[0].source, RotationSource::OnDemand);
        assert_eq!(detail.jobs[0].status, RotationJobStatus::Pending);
    }

    /// A config that has never rotated is not an error - it has no history.
    #[test]
    fn a_detail_payload_without_jobs_has_no_jobs() {
        let detail =
            RotationConfigDetail::try_from(sample_detail_response(None)).expect("no jobs is fine");

        assert!(detail.jobs.is_empty());
    }

    #[test]
    fn a_malformed_job_fails_the_whole_detail() {
        let malformed = PamRotationJobResponseModel {
            rotation_config_id: None,
            ..sample_job(job_id())
        };

        let result = RotationConfigDetail::try_from(sample_detail_response(Some(vec![malformed])));

        assert!(matches!(result, Err(RotationError::MissingField(_))));
    }

    #[test]
    fn a_create_request_carries_every_field() {
        let model = CreateRotationConfigRequestModel::from(create_request());

        assert_eq!(model.cipher_id, Uuid::from(cipher_id()));
        assert_eq!(model.target_system_id, Uuid::from(target_system_id()));
        assert_eq!(model.account_identity, "svc_rotation");
        assert_eq!(model.terminate_sessions, Some(true));
        assert_eq!(model.schedule_cron.as_deref(), Some("0 0 0 * * ?"));
        assert_eq!(model.rotate_on_access_end, Some(true));
    }

    /// Clearing a schedule has to send `null`, not omit the field - an omitted cron would leave the
    /// server's stored schedule in place and the config would keep rotating.
    #[test]
    fn clearing_the_schedule_sends_an_explicit_absence() {
        let model = UpdateRotationConfigRequestModel::from(RotationConfigUpdateRequest {
            schedule_cron: None,
            ..update_request()
        });

        assert_eq!(model.schedule_cron, None);
        let body = serde_json::to_value(&model).expect("it serializes");
        assert_eq!(
            body["scheduleCron"],
            serde_json::Value::Null,
            "the server must be told the schedule is gone"
        );
    }

    #[test]
    fn an_update_request_carries_every_field() {
        let model = UpdateRotationConfigRequestModel::from(update_request());

        assert_eq!(model.account_identity, "svc_rotation");
        assert_eq!(model.terminate_sessions, Some(true));
        assert_eq!(model.schedule_cron.as_deref(), Some("0 0 0 * * ?"));
        assert_eq!(model.rotate_on_access_end, Some(true));
    }

    #[tokio::test]
    async fn list_maps_the_organizations_configs() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get_all()
                .withf(|org_id| *org_id == Uuid::from(organization_id()))
                .returning(move |_org_id| {
                    Ok(PamRotationConfigResponseModelListResponseModel {
                        data: Some(vec![sample_response()]),
                        ..Default::default()
                    })
                })
                .once();
        });

        let configs = client(api_client)
            .list(organization_id())
            .await
            .expect("the list succeeds");

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].id, config_id());
    }

    #[tokio::test]
    async fn an_organization_with_no_configs_lists_empty() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamRotationConfigResponseModelListResponseModel::default())
                })
                .once();
        });

        let configs = client(api_client)
            .list(organization_id())
            .await
            .expect("an absent list is not an error");

        assert!(configs.is_empty());
    }

    #[tokio::test]
    async fn list_fails_if_any_config_is_malformed() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamRotationConfigResponseModelListResponseModel {
                        data: Some(vec![
                            sample_response(),
                            PamRotationConfigResponseModel {
                                cipher_id: None,
                                ..sample_response()
                            },
                        ]),
                        ..Default::default()
                    })
                })
                .once();
        });

        let result = client(api_client).list(organization_id()).await;

        assert!(matches!(result, Err(RotationError::MissingField(_))));
    }

    #[tokio::test]
    async fn list_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).list(organization_id()).await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    #[tokio::test]
    async fn get_reads_the_requested_config_with_its_history() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| {
                    Ok(sample_detail_response(Some(vec![sample_job(job_id())])))
                })
                .once();
        });

        let detail = client(api_client)
            .get(organization_id(), config_id())
            .await
            .expect("the read succeeds");

        assert_eq!(detail.config.id, config_id());
        assert_eq!(detail.jobs.len(), 1);
    }

    #[tokio::test]
    async fn get_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_get()
                .returning(move |_org_id, _id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::NOT_FOUND,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).get(organization_id(), config_id()).await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    #[tokio::test]
    async fn create_sends_the_request_and_returns_the_stored_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_post()
                .withf(|org_id, request| {
                    *org_id == Uuid::from(organization_id())
                        && request.cipher_id == Uuid::from(cipher_id())
                        && request.target_system_id == Uuid::from(target_system_id())
                        && request.account_identity == "svc_rotation"
                        && request.schedule_cron.as_deref() == Some("0 0 0 * * ?")
                })
                .returning(move |_org_id, _request| Ok(sample_detail_response(None)))
                .once();
        });

        let detail = client(api_client)
            .create(organization_id(), create_request())
            .await
            .expect("creation succeeds");

        assert_eq!(detail.config.id, config_id());
    }

    /// A config with no schedule is valid - it rotates on demand or on access end only.
    #[tokio::test]
    async fn a_config_can_be_created_without_a_schedule() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_post()
                .withf(|_org_id, request| request.schedule_cron.is_none())
                .returning(move |_org_id, _request| Ok(sample_detail_response(None)))
                .once();
        });

        client(api_client)
            .create(
                organization_id(),
                RotationConfigCreateRequest {
                    schedule_cron: None,
                    ..create_request()
                },
            )
            .await
            .expect("creation succeeds");
    }

    /// The mock has no expectations, so any call to the server fails the test.
    #[tokio::test]
    async fn create_rejects_an_invalid_request_before_calling_the_server() {
        for (request, expected) in [
            (
                RotationConfigCreateRequest {
                    account_identity: "   ".to_string(),
                    ..create_request()
                },
                RotationValidationError::InvalidAccountIdentity,
            ),
            (
                RotationConfigCreateRequest {
                    // A 5-field UNIX cron, which Quartz would misread field by field.
                    schedule_cron: Some("0 0 * * *".to_string()),
                    ..create_request()
                },
                RotationValidationError::InvalidCron,
            ),
        ] {
            let result = client(ApiClient::new_mocked(|_| {}))
                .create(organization_id(), request)
                .await;

            assert!(
                matches!(result, Err(RotationError::Validation(ref actual)) if *actual == expected),
                "expected {expected:?}, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn update_sends_the_request_to_the_requested_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_put()
                .withf(|org_id, id, request| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(config_id())
                        && request.account_identity == "svc_rotation"
                        && request.rotate_on_access_end == Some(true)
                })
                .returning(move |_org_id, _id, _request| Ok(sample_detail_response(None)))
                .once();
        });

        let detail = client(api_client)
            .update(organization_id(), config_id(), update_request())
            .await
            .expect("the update succeeds");

        assert_eq!(detail.config.id, config_id());
    }

    #[tokio::test]
    async fn update_rejects_an_invalid_request_before_calling_the_server() {
        for (request, expected) in [
            (
                RotationConfigUpdateRequest {
                    account_identity: String::new(),
                    ..update_request()
                },
                RotationValidationError::InvalidAccountIdentity,
            ),
            (
                RotationConfigUpdateRequest {
                    schedule_cron: Some("not a cron".to_string()),
                    ..update_request()
                },
                RotationValidationError::InvalidCron,
            ),
        ] {
            let result = client(ApiClient::new_mocked(|_| {}))
                .update(organization_id(), config_id(), request)
                .await;

            assert!(
                matches!(result, Err(RotationError::Validation(ref actual)) if *actual == expected),
                "expected {expected:?}, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn pause_targets_the_requested_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_pause()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .pause(organization_id(), config_id())
            .await
            .expect("pausing succeeds");
    }

    #[tokio::test]
    async fn resume_targets_the_requested_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_resume()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .resume(organization_id(), config_id())
            .await
            .expect("resuming succeeds");
    }

    /// `rotate_now` maps onto the server's `rotate` route. The four unit-returning actions here are
    /// distinguishable only by which route they hit, so each is pinned to its own.
    #[tokio::test]
    async fn rotate_now_dispatches_an_on_demand_rotation() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_rotate()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .rotate_now(organization_id(), config_id())
            .await
            .expect("dispatching succeeds");
    }

    #[tokio::test]
    async fn record_manual_rotation_records_against_the_requested_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_record_manual()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .record_manual_rotation(organization_id(), config_id())
            .await
            .expect("recording succeeds");
    }

    #[tokio::test]
    async fn delete_targets_the_requested_config() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_delete()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .delete(organization_id(), config_id())
            .await
            .expect("deleting succeeds");
    }

    /// The server's cooldown refusal is the expected failure on this route, so it has to reach the
    /// caller rather than read as a dispatched rotation.
    #[tokio::test]
    async fn rotate_now_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_configs_api
                .expect_rotate()
                .returning(move |_org_id, _id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client)
            .rotate_now(organization_id(), config_id())
            .await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    /// The client method exists so non-Rust callers reach the same predicates the Rust API has on
    /// [`RotationConfig::actions`]; it must not drift from them.
    #[test]
    fn the_client_derives_the_same_actions_as_the_config() {
        let config = RotationConfig::try_from(sample_response()).expect("the payload is valid");

        for status in [
            None,
            Some(TargetSystemStatus::Active),
            Some(TargetSystemStatus::Disabled),
            Some(TargetSystemStatus::Unknown),
        ] {
            assert_eq!(
                client(ApiClient::new_mocked(|_| {})).actions(config.clone(), status),
                config.actions(status),
                "for {status:?}"
            );
        }
    }
}
