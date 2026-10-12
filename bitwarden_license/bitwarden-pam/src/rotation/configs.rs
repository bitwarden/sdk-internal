use std::sync::Arc;

use bitwarden_api_api::models::{
    CreateRotationConfigRequestModel, PamRotationConfigDetailResponseModel,
    PamRotationConfigResponseModel, PamTargetSystemResponseModel, UpdateRotationConfigRequestModel,
};
use bitwarden_core::{
    FromClient, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{KeyStore, KeyStoreContext};
use bitwarden_pam_sealed::seal_rotation_config;
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
    seal::{rotation_config_sealed_data, unseal_config},
    target_systems::TargetSystem,
    validate::{RotationValidationError, validate_config_request},
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
    /// The vault cipher whose credential this config manages. Its name is vault data, so decrypt
    /// it from the caller's own cipher state.
    pub cipher_id: CipherId,
    /// The target system credentials are rotated against.
    pub target_system_id: TargetSystemId,
    /// The target system's display name, as of this read.
    pub target_system_name: String,
    /// The target system's rotation method, which decides the actions the config offers.
    pub target_system_method: TargetSystemMethod,
    /// The config's security-relevant fields, read from the unsealed blob — `None` whenever the
    /// blob could not be verified: missing, fails to unseal under the organization key, or its
    /// sealed IDs disagree with this row's own plaintext copies. A rotation config always
    /// carries a blob (unlike a target system, there is no "not set up yet" state), so `None`
    /// here always means "something is wrong with this row". The item itself is still returned:
    /// one config's bad blob never fails [`RotationConfigsClient::list`].
    pub sealed: Option<RotationConfigSealedFields>,
    /// The Quartz cron expression driving scheduled rotation, or `None` for no schedule.
    pub schedule_cron: Option<String>,
    /// Whether the credential is rotated at the end of an access lease over the cipher.
    pub rotate_on_access_end: bool,
    /// False stops new rotation jobs from dispatching; jobs in flight run to completion.
    pub enabled: bool,
    /// The most recent completed rotation (UTC), or `None` absent any rotation.
    pub last_rotation_at: Option<DateTime<Utc>>,
    /// When the config is next due for rotation (UTC), or `None` when nothing is due.
    pub next_rotation_at: Option<DateTime<Utc>>,
    /// Whether the config has a pending or claimed job, or a timed-out one the sweep has not yet
    /// recorded.
    pub has_active_job: bool,
    /// Whether a manual-method config is waiting for an operator to record an out-of-band
    /// rotation.
    pub awaiting_manual_rotation: bool,
    /// The config's creation time (UTC).
    pub creation_date: DateTime<Utc>,
    /// The config's last-modified time (UTC).
    pub revision_date: DateTime<Utc>,
}

/// The security-relevant fields of a rotation config, read from its unsealed blob. The server
/// never sees these: it stores only the opaque blob they came from.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfigSealedFields {
    /// The account within the target system: a username, UPN, or service-account name.
    pub account_identity: String,
    /// Whether the connector terminates the account's sessions after a successful rotation.
    pub terminate_sessions: bool,
}

impl RotationConfig {
    /// Which actions this config offers, given the status of its target system.
    ///
    /// See [`rotation_config_actions`] for how an unloaded target system's `target_status` is
    /// treated. Note that a `PendingSeal` target cannot be distinguished here from any other
    /// non-`Active` status: the config response does not carry the target's status, only its
    /// `target_system_method`, so callers that care about `PendingSeal` specifically must look it
    /// up separately via [`crate::TargetSystemsClient::list`].
    pub fn actions(&self, target_status: Option<TargetSystemStatus>) -> RotationConfigActions {
        rotation_config_actions(self, target_status)
    }

    /// Builds a [`RotationConfig`] from the server's response, unsealing its blob against `ctx`.
    /// Only fails on a structurally malformed response; a blob that fails to unseal or validate
    /// degrades [`Self::sealed`] to `None` rather than failing, so one bad item cannot fail
    /// [`RotationConfigsClient::list`].
    ///
    /// `organization_id` must be the id the caller queried under, not read back from
    /// `response.organization_id`: the latter is server-controlled, and a caller holding more
    /// than one organization's key must not let a hostile server substitute another
    /// organization's validly-sealed blob into this one's list. A disagreement between the two
    /// is treated as unverifiable (`sealed: None`) rather than trusting either copy.
    fn from_response(
        organization_id: OrganizationId,
        response: PamRotationConfigResponseModel,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, RotationError> {
        let id = RotationConfigId::new(require!(response.id));
        let cipher_id = CipherId::new(require!(response.cipher_id));
        let target_system_id = TargetSystemId::new(require!(response.target_system_id));

        let sealed = if response.organization_id == Some(organization_id.into()) {
            unseal_config(
                response.sealed_data.as_deref(),
                id,
                target_system_id,
                cipher_id.into(),
                organization_id,
                ctx,
            )
        } else {
            tracing::debug!("PAM rotation config organization_id mismatch");
            None
        };

        Ok(Self {
            id,
            organization_id,
            cipher_id,
            target_system_id,
            target_system_name: response.target_system_name.unwrap_or_default(),
            target_system_method: require!(response.target_system_method).into(),
            sealed,
            schedule_cron: response.schedule_cron,
            rotate_on_access_end: response.rotate_on_access_end.unwrap_or(false),
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

impl RotationConfigDetail {
    fn from_response(
        organization_id: OrganizationId,
        response: PamRotationConfigDetailResponseModel,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, RotationError> {
        let jobs = response
            .jobs
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(RotationJob::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        // The server flattens the config's own fields onto the detail payload, so the list model is
        // rebuilt from it.
        let config = RotationConfig::from_response(
            organization_id,
            PamRotationConfigResponseModel {
                object: response.object,
                id: response.id,
                organization_id: response.organization_id,
                cipher_id: response.cipher_id,
                target_system_id: response.target_system_id,
                target_system_name: response.target_system_name,
                target_system_method: response.target_system_method,
                sealed_data: response.sealed_data,
                schedule_cron: response.schedule_cron,
                rotate_on_access_end: response.rotate_on_access_end,
                next_rotation_at: response.next_rotation_at,
                enabled: response.enabled,
                last_rotation_at: response.last_rotation_at,
                has_active_job: response.has_active_job,
                awaiting_manual_rotation: response.awaiting_manual_rotation,
                creation_date: response.creation_date,
                revision_date: response.revision_date,
            },
            ctx,
        )?;

        Ok(Self { config, jobs })
    }
}

/// Request to create or update a rotation config. [`RotationConfigsClient::update`] takes this
/// same shape — see its docs for why.
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
    /// Whether to terminate the account's sessions after a successful rotation. Only allowed when
    /// the target system's unsealed `supports_session_termination` is confirmed `true`; see
    /// [`RotationConfigsClient::create`].
    pub terminate_sessions: bool,
    /// A Quartz cron expression, or `None` for no scheduled rotation.
    pub schedule_cron: Option<String>,
    /// Whether to rotate at the end of an access lease over the cipher.
    pub rotate_on_access_end: bool,
}

/// Client for PAM managed-credential (rotation config) operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct RotationConfigsClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
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

        let mut ctx = self.key_store.context_mut();
        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|item| RotationConfig::from_response(organization_id, item, &mut ctx))
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

        let mut ctx = self.key_store.context_mut();
        RotationConfigDetail::from_response(organization_id, response, &mut ctx)
    }

    /// Validates, seals, and creates a rotation config. Before sealing, fetches the organization's
    /// target systems to validate `target_system_id`: the target must exist, and must have
    /// verified sealed fields (see [`TargetSystem::sealed`]) unless it is still
    /// [`PendingSeal`](TargetSystemStatus::PendingSeal) — a `PendingSeal` target is allowed,
    /// since a config may be created before its target finishes setup (it just does not run
    /// until the target is sealed). If `terminate_sessions` is requested, the target's unsealed
    /// `supports_session_termination` must be confirmed `Some(true)`; a target with no verified
    /// sealed fields (`PendingSeal`, or unverifiable) has an unknown capability, so
    /// `terminate_sessions` must be `false` against one.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        request: RotationConfigCreateRequest,
    ) -> Result<RotationConfigDetail, RotationError> {
        validate_config_request(&request)?;
        self.validate_target(
            organization_id,
            request.target_system_id,
            request.terminate_sessions,
        )
        .await?;

        let sealed_data = self.seal(organization_id, &request)?;
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .post(
                organization_id.into(),
                CreateRotationConfigRequestModel {
                    cipher_id: request.cipher_id.into(),
                    target_system_id: request.target_system_id.into(),
                    sealed_data,
                    schedule_cron: request.schedule_cron.clone(),
                    rotate_on_access_end: Some(request.rotate_on_access_end),
                },
            )
            .await?;

        let mut ctx = self.key_store.context_mut();
        RotationConfigDetail::from_response(organization_id, response, &mut ctx)
    }

    /// Re-seals and replaces a rotation config's blob wholesale: a fresh content-encryption key,
    /// the complete sealed content built from `request`. `cipher_id` and `target_system_id`
    /// cannot actually change (the server does not accept them on this route, and a config has no
    /// way to move to a different cipher or target), but [`RotationConfigCreateRequest`] is reused
    /// here anyway: since each `PUT` replaces the blob wholesale rather than patching it, every
    /// field the blob carries has to be resupplied every time. Pass the config's current
    /// `cipher_id`/`target_system_id` back unchanged (read them from a prior [`Self::list`] or
    /// [`Self::get`]).
    ///
    /// `GET`s the existing config first and rejects rather than silently sealing a blob that
    /// disagrees with the server: a `cipher_id` or `target_system_id` different from the config's
    /// own plaintext copies is refused
    /// ([`RotationValidationError::RotationConfigImmutableFieldMismatch`]) before anything is
    /// sealed or sent.
    ///
    /// Applies the same target-system validation as [`Self::create`].
    pub async fn update(
        &self,
        organization_id: OrganizationId,
        id: RotationConfigId,
        request: RotationConfigCreateRequest,
    ) -> Result<RotationConfigDetail, RotationError> {
        validate_config_request(&request)?;

        let existing = self.get(organization_id, id).await?;
        if existing.config.cipher_id != request.cipher_id
            || existing.config.target_system_id != request.target_system_id
        {
            return Err(RotationValidationError::RotationConfigImmutableFieldMismatch.into());
        }

        self.validate_target(
            organization_id,
            request.target_system_id,
            request.terminate_sessions,
        )
        .await?;

        let sealed_data = self.seal(organization_id, &request)?;
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_configs_api()
            .put(
                organization_id.into(),
                id.into(),
                UpdateRotationConfigRequestModel {
                    sealed_data,
                    schedule_cron: request.schedule_cron,
                    rotate_on_access_end: Some(request.rotate_on_access_end),
                },
            )
            .await?;

        let mut ctx = self.key_store.context_mut();
        RotationConfigDetail::from_response(organization_id, response, &mut ctx)
    }

    /// Seals `request`'s security-relevant fields under the organization key.
    fn seal(
        &self,
        organization_id: OrganizationId,
        request: &RotationConfigCreateRequest,
    ) -> Result<String, RotationError> {
        let organization_key = SymmetricKeySlotId::Organization(organization_id);
        let mut ctx = self.key_store.context_mut();
        if !ctx.has_symmetric_key(organization_key) {
            return Err(RotationError::MissingOrganizationKey);
        }

        let data = rotation_config_sealed_data(
            request.target_system_id,
            request.cipher_id.into(),
            request.account_identity.clone(),
            request.terminate_sessions,
        );
        Ok(seal_rotation_config::<KeySlotIds>(
            data,
            &organization_key,
            &mut ctx,
        )?)
    }

    /// Fetches the organization's target systems and validates `target_system_id` against
    /// `terminate_sessions`: the target must exist and must have verified sealed fields (see
    /// [`TargetSystem::sealed`]) unless it is still `PendingSeal` (allowed — a config may be
    /// created before its target finishes setup); if `terminate_sessions` is requested, the
    /// target's unsealed `supports_session_termination` must be `Some(true)`.
    async fn validate_target(
        &self,
        organization_id: OrganizationId,
        target_system_id: TargetSystemId,
        terminate_sessions: bool,
    ) -> Result<(), RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .get_all(organization_id.into())
            .await?;

        let item: PamTargetSystemResponseModel = response
            .data
            .unwrap_or_default()
            .into_iter()
            .find(|item| item.id == Some(target_system_id.into()))
            .ok_or(RotationError::TargetSystemNotFound)?;

        let target = {
            let mut ctx = self.key_store.context_mut();
            TargetSystem::from_response(organization_id, item, &mut ctx)?
        };

        if target.status != TargetSystemStatus::PendingSeal && target.sealed.is_none() {
            return Err(RotationValidationError::TargetSystemSealInvalid.into());
        }

        let supports_termination = target
            .sealed
            .as_ref()
            .and_then(|sealed| sealed.supports_session_termination);
        if terminate_sessions && supports_termination != Some(true) {
            return Err(RotationValidationError::SessionTerminationUnsupported.into());
        }

        Ok(())
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

    /// Which actions a config offers, given the status of its target system. Exposed here because
    /// a tsify struct crosses the WASM boundary as plain data, without [`RotationConfig::actions`].
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
            PamTargetSystemResponseModelListResponseModel,
            PamTargetSystemStatus as ApiTargetSystemStatus,
        },
    };
    use bitwarden_core::key_management::create_test_crypto_with_user_and_org_key;
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_pam_sealed::{
        RotationConfigSealedV1, SealedPasswordPolicy, SealedTargetSystemKind,
        SealedTargetSystemMethod, TargetSystemSealedV1, seal_target_system, unseal_rotation_config,
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

    fn organization_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac)
    }

    fn client(api_client: ApiClient) -> RotationConfigsClient {
        client_with_org_key(api_client, organization_key())
    }

    fn client_with_org_key(
        api_client: ApiClient,
        organization_key: SymmetricCryptoKey,
    ) -> RotationConfigsClient {
        RotationConfigsClient {
            key_store: create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key,
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn seal_config_with(
        organization_key: &SymmetricCryptoKey,
        data: RotationConfigSealedV1,
    ) -> String {
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();
        seal_rotation_config::<KeySlotIds>(
            data,
            &SymmetricKeySlotId::Organization(organization_id()),
            &mut ctx,
        )
        .expect("sealing succeeds")
    }

    fn seal_target_with(
        organization_key: &SymmetricCryptoKey,
        data: TargetSystemSealedV1,
    ) -> String {
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();
        seal_target_system::<KeySlotIds>(
            data,
            &SymmetricKeySlotId::Organization(organization_id()),
            &mut ctx,
        )
        .expect("sealing succeeds")
    }

    fn sample_sealed_data() -> RotationConfigSealedV1 {
        RotationConfigSealedV1 {
            target_system_id: target_system_id().into(),
            cipher_id: cipher_id().into(),
            account_identity: "svc_rotation".to_string(),
            terminate_sessions: true,
        }
    }

    /// A payload with every optional field populated, so a test that clears one is unambiguous
    /// about which field it is exercising.
    fn sample_response(organization_key: &SymmetricCryptoKey) -> PamRotationConfigResponseModel {
        PamRotationConfigResponseModel {
            id: Some(config_id().into()),
            organization_id: Some(organization_id().into()),
            cipher_id: Some(cipher_id().into()),
            target_system_id: Some(target_system_id().into()),
            target_system_name: Some("Prod SQL".to_string()),
            target_system_method: Some(ApiTargetSystemMethod::Automatic),
            sealed_data: Some(seal_config_with(organization_key, sample_sealed_data())),
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
        organization_key: &SymmetricCryptoKey,
        jobs: Option<Vec<PamRotationJobResponseModel>>,
    ) -> PamRotationConfigDetailResponseModel {
        let config = sample_response(organization_key);
        PamRotationConfigDetailResponseModel {
            object: config.object,
            id: config.id,
            organization_id: config.organization_id,
            cipher_id: config.cipher_id,
            target_system_id: config.target_system_id,
            target_system_name: config.target_system_name,
            target_system_method: config.target_system_method,
            sealed_data: config.sealed_data,
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

    /// A sealed, active, automatic target system supporting session termination, matching
    /// `target_system_id()` — the shape `validate_target` needs to allow `terminate_sessions`.
    fn terminable_target_response(
        organization_key: &SymmetricCryptoKey,
    ) -> PamTargetSystemResponseModel {
        PamTargetSystemResponseModel {
            id: Some(target_system_id().into()),
            organization_id: Some(organization_id().into()),
            name: Some("Prod SQL".to_string()),
            method: Some(ApiTargetSystemMethod::Automatic),
            status: Some(ApiTargetSystemStatus::Active),
            sealed_data: Some(seal_target_with(
                organization_key,
                TargetSystemSealedV1 {
                    target_system_id: target_system_id().into(),
                    method: SealedTargetSystemMethod::Automatic,
                    kind: Some(SealedTargetSystemKind::Mssql),
                    password_policy: SealedPasswordPolicy {
                        min_length: 14,
                        max_length: 20,
                        include_uppercase: true,
                        include_lowercase: true,
                        include_digits: true,
                        include_symbols: false,
                    },
                    supports_session_termination: Some(true),
                },
            )),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            revision_date: Some("2026-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn target_systems_response(
        targets: Vec<PamTargetSystemResponseModel>,
    ) -> PamTargetSystemResponseModelListResponseModel {
        PamTargetSystemResponseModelListResponseModel {
            data: Some(targets),
            ..Default::default()
        }
    }

    #[test]
    fn a_full_payload_maps_every_field() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let config = RotationConfig::from_response(
            organization_id(),
            sample_response(&organization_key),
            &mut ctx,
        )
        .expect("the payload is valid");

        assert_eq!(config.id, config_id());
        assert_eq!(config.organization_id, organization_id());
        assert_eq!(config.cipher_id, cipher_id());
        assert_eq!(config.target_system_id, target_system_id());
        assert_eq!(config.target_system_name, "Prod SQL");
        assert_eq!(config.target_system_method, TargetSystemMethod::Automatic);
        let sealed = config.sealed.expect("the blob is sealed");
        assert_eq!(sealed.account_identity, "svc_rotation");
        assert!(sealed.terminate_sessions);
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

    /// A blob sealed for a different config (wrong cipher) must degrade the item to
    /// `sealed: None`, never fail the conversion outright.
    #[test]
    fn an_invalid_blob_degrades_to_no_sealed_fields() {
        let organization_key = organization_key();
        let wrong_cipher_blob = seal_config_with(
            &organization_key,
            RotationConfigSealedV1 {
                cipher_id: uuid!("99999999-9999-9999-9999-999999999999"),
                ..sample_sealed_data()
            },
        );

        for sealed_data in [
            Some("not a sealed blob".to_string()),
            Some(wrong_cipher_blob),
            None,
        ] {
            let store = create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key.clone(),
            );
            let mut ctx = store.context_mut();

            let response = PamRotationConfigResponseModel {
                sealed_data,
                ..sample_response(&organization_key)
            };

            let config = RotationConfig::from_response(organization_id(), response, &mut ctx)
                .expect("the payload is valid");

            assert_eq!(config.sealed, None);
        }
    }

    /// A hostile server could echo a different organization's id on an item served as part of
    /// org A's `list`, hoping a caller who also holds org B's key (a multi-org admin) unseals
    /// org B's validly-sealed blob as if it belonged to this org-A row. The key used must always
    /// be the queried `organization_id`, never `response.organization_id` — so a blob that would
    /// otherwise unseal and validate perfectly under org B's key must still read `sealed: None`
    /// here, because it was requested for org A.
    #[test]
    fn a_blob_from_a_different_organization_is_not_trusted() {
        let org_a = organization_id();
        let org_b = OrganizationId::new(uuid!("66666666-6666-6666-6666-666666666666"));
        let org_a_key = organization_key();
        let org_b_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // A blob that validly seals and would validate (right ids) under org B's key — the
        // caller holds both orgs' keys, as a multi-org admin would.
        let org_b_blob = seal_config_with(&org_b_key, sample_sealed_data());

        let store = KeyStore::<KeySlotIds>::default();
        {
            let mut ctx = store.context_mut();
            #[allow(deprecated)]
            ctx.set_symmetric_key(SymmetricKeySlotId::Organization(org_a), org_a_key)
                .expect("mutable context");
            #[allow(deprecated)]
            ctx.set_symmetric_key(SymmetricKeySlotId::Organization(org_b), org_b_key)
                .expect("mutable context");
        }

        let response = PamRotationConfigResponseModel {
            // The server claims this item belongs to org B, even though it is being served as
            // part of org A's list.
            organization_id: Some(org_b.into()),
            sealed_data: Some(org_b_blob),
            ..sample_response(&organization_key())
        };

        let mut ctx = store.context_mut();
        let config = RotationConfig::from_response(org_a, response, &mut ctx)
            .expect("the payload is still structurally valid");

        assert_eq!(config.organization_id, org_a);
        assert_eq!(config.sealed, None);
    }

    #[test]
    fn an_omitted_enabled_flag_means_the_config_is_active() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let config = RotationConfig::from_response(
            organization_id(),
            PamRotationConfigResponseModel {
                enabled: None,
                ..sample_response(&organization_key)
            },
            &mut ctx,
        )
        .expect("the payload is valid");

        assert!(config.enabled);
        assert!(config.actions(Some(TargetSystemStatus::Active)).can_pause);
        assert!(!config.actions(Some(TargetSystemStatus::Active)).can_resume);
    }

    #[test]
    fn the_remaining_absent_fields_default_to_not_set() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let config = RotationConfig::from_response(
            organization_id(),
            PamRotationConfigResponseModel {
                target_system_name: None,
                schedule_cron: None,
                rotate_on_access_end: None,
                last_rotation_at: None,
                next_rotation_at: None,
                has_active_job: None,
                awaiting_manual_rotation: None,
                ..sample_response(&organization_key)
            },
            &mut ctx,
        )
        .expect("the payload is valid");

        assert_eq!(config.target_system_name, "");
        assert_eq!(config.schedule_cron, None);
        assert!(!config.rotate_on_access_end);
        assert_eq!(config.last_rotation_at, None);
        assert_eq!(config.next_rotation_at, None);
        assert!(!config.has_active_job);
        assert!(!config.awaiting_manual_rotation);
    }

    #[test]
    fn a_missing_required_field_is_reported_rather_than_defaulted() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        for response in [
            PamRotationConfigResponseModel {
                id: None,
                ..sample_response(&organization_key)
            },
            // Note: `organization_id: None` is deliberately not a case here — a mismatched or
            // missing `organization_id` degrades `sealed` to `None` rather than failing the
            // whole item; see `a_blob_from_a_different_organization_is_not_trusted`.
            PamRotationConfigResponseModel {
                cipher_id: None,
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                target_system_id: None,
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                target_system_method: None,
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                creation_date: None,
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                revision_date: None,
                ..sample_response(&organization_key)
            },
        ] {
            assert!(matches!(
                RotationConfig::from_response(organization_id(), response, &mut ctx),
                Err(RotationError::MissingField(_))
            ));
        }
    }

    #[test]
    fn an_unparseable_date_is_reported() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        for response in [
            PamRotationConfigResponseModel {
                creation_date: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                revision_date: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                last_rotation_at: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
            PamRotationConfigResponseModel {
                next_rotation_at: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
        ] {
            assert!(matches!(
                RotationConfig::from_response(organization_id(), response, &mut ctx),
                Err(RotationError::Chrono(_))
            ));
        }
    }

    #[test]
    fn an_unrecognized_method_degrades_to_unknown() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let config = RotationConfig::from_response(
            organization_id(),
            PamRotationConfigResponseModel {
                target_system_method: Some(ApiTargetSystemMethod::__Unknown(9)),
                ..sample_response(&organization_key)
            },
            &mut ctx,
        )
        .expect("an unknown method still maps");

        assert_eq!(config.target_system_method, TargetSystemMethod::Unknown);
    }

    /// The detail conversion hand-copies each field of the flattened payload, so a dropped one
    /// would silently read as absent.
    #[test]
    fn the_detail_payload_yields_the_same_config_as_the_list_payload() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let detail = RotationConfigDetail::from_response(
            organization_id(),
            sample_detail_response(&organization_key, Some(vec![sample_job(job_id())])),
            &mut ctx,
        )
        .expect("the payload is valid");

        assert_eq!(
            detail.config,
            RotationConfig::from_response(
                organization_id(),
                sample_response(&organization_key),
                &mut ctx
            )
            .expect("the payload is valid")
        );
    }

    #[test]
    fn detail_jobs_keep_the_order_the_server_sent() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let second = uuid!("66666666-6666-6666-6666-666666666666");
        let detail = RotationConfigDetail::from_response(
            organization_id(),
            sample_detail_response(
                &organization_key,
                Some(vec![sample_job(job_id()), sample_job(second)]),
            ),
            &mut ctx,
        )
        .expect("the payload is valid");

        let ids: Vec<Uuid> = detail.jobs.iter().map(|job| job.id.into()).collect();
        assert_eq!(ids, [job_id(), second]);
        assert_eq!(detail.jobs[0].source, RotationSource::OnDemand);
        assert_eq!(detail.jobs[0].status, RotationJobStatus::Pending);
    }

    /// A config that has never rotated has no history, which is not an error.
    #[test]
    fn a_detail_payload_without_jobs_has_no_jobs() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let detail = RotationConfigDetail::from_response(
            organization_id(),
            sample_detail_response(&organization_key, None),
            &mut ctx,
        )
        .expect("no jobs is fine");

        assert!(detail.jobs.is_empty());
    }

    #[test]
    fn a_malformed_job_fails_the_whole_detail() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let malformed = PamRotationJobResponseModel {
            rotation_config_id: None,
            ..sample_job(job_id())
        };

        let result = RotationConfigDetail::from_response(
            organization_id(),
            sample_detail_response(&organization_key, Some(vec![malformed])),
            &mut ctx,
        );

        assert!(matches!(result, Err(RotationError::MissingField(_))));
    }

    #[tokio::test]
    async fn list_maps_the_organizations_configs() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get_all()
                    .withf(|org_id| *org_id == Uuid::from(organization_id()))
                    .returning(move |_org_id| {
                        Ok(PamRotationConfigResponseModelListResponseModel {
                            data: Some(vec![sample_response(&organization_key)]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let configs = client_with_org_key(api_client, organization_key)
            .list(organization_id())
            .await
            .expect("the list succeeds");

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].id, config_id());
        assert!(configs[0].sealed.is_some());
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

    /// One invalid item (a garbage blob) must not fail the whole list.
    #[tokio::test]
    async fn list_returns_the_rest_when_one_item_has_an_invalid_blob() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        let bad = PamRotationConfigResponseModel {
                            id: Some(uuid!("77777777-7777-7777-7777-777777777777")),
                            sealed_data: Some("not a sealed blob".to_string()),
                            ..sample_response(&organization_key)
                        };
                        Ok(PamRotationConfigResponseModelListResponseModel {
                            data: Some(vec![sample_response(&organization_key), bad]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let configs = client_with_org_key(api_client, organization_key)
            .list(organization_id())
            .await
            .expect("one invalid item does not fail the list");

        assert_eq!(configs.len(), 2);
        assert!(configs[0].sealed.is_some());
        assert_eq!(configs[1].sealed, None);
    }

    #[tokio::test]
    async fn list_fails_if_a_required_field_is_missing() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(PamRotationConfigResponseModelListResponseModel {
                            data: Some(vec![PamRotationConfigResponseModel {
                                cipher_id: None,
                                ..sample_response(&organization_key)
                            }]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .list(organization_id())
            .await;

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
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get()
                    .withf(|org_id, id| {
                        *org_id == Uuid::from(organization_id()) && *id == Uuid::from(config_id())
                    })
                    .returning(move |_org_id, _id| {
                        Ok(sample_detail_response(
                            &organization_key,
                            Some(vec![sample_job(job_id())]),
                        ))
                    })
                    .once();
            })
        };

        let detail = client_with_org_key(api_client, organization_key)
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
    async fn create_validates_the_target_seals_and_sends_the_request() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                let target_key = organization_key.clone();
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(target_systems_response(vec![terminable_target_response(
                            &target_key,
                        )]))
                    })
                    .once();

                let config_key = organization_key.clone();
                mock.pam_access_connector_rotation_configs_api
                    .expect_post()
                    .withf(move |org_id, request| {
                        if *org_id != Uuid::from(organization_id())
                            || request.cipher_id != Uuid::from(cipher_id())
                            || request.target_system_id != Uuid::from(target_system_id())
                            || request.schedule_cron.as_deref() != Some("0 0 0 * * ?")
                        {
                            return false;
                        }

                        let store = create_test_crypto_with_user_and_org_key(
                            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                            organization_id(),
                            config_key.clone(),
                        );
                        let mut ctx = store.context_mut();
                        let unsealed = unseal_rotation_config::<KeySlotIds>(
                            &request.sealed_data,
                            &SymmetricKeySlotId::Organization(organization_id()),
                            &mut ctx,
                        )
                        .expect("the blob unseals under the organization key");

                        unsealed.target_system_id == Uuid::from(target_system_id())
                            && unsealed.cipher_id == Uuid::from(cipher_id())
                            && unsealed.account_identity == "svc_rotation"
                            && unsealed.terminate_sessions
                    })
                    .returning(move |_org_id, _request| {
                        Ok(sample_detail_response(&organization_key, None))
                    })
                    .once();
            })
        };

        let detail = client_with_org_key(api_client, organization_key)
            .create(organization_id(), create_request())
            .await
            .expect("creation succeeds");

        assert_eq!(detail.config.id, config_id());
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

    /// The target not supporting session termination must reject `terminate_sessions: true`,
    /// after fetching the target but before writing anything.
    #[tokio::test]
    async fn create_rejects_terminate_sessions_on_an_unsupported_target() {
        let organization_key = organization_key();
        let api_client = {
            let target_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        let response = PamTargetSystemResponseModel {
                            sealed_data: Some(seal_target_with(
                                &target_key,
                                TargetSystemSealedV1 {
                                    target_system_id: target_system_id().into(),
                                    method: SealedTargetSystemMethod::Automatic,
                                    kind: Some(SealedTargetSystemKind::Mssql),
                                    password_policy: SealedPasswordPolicy {
                                        min_length: 14,
                                        max_length: 20,
                                        include_uppercase: true,
                                        include_lowercase: true,
                                        include_digits: true,
                                        include_symbols: false,
                                    },
                                    supports_session_termination: Some(false),
                                },
                            )),
                            ..terminable_target_response(&target_key)
                        };
                        Ok(target_systems_response(vec![response]))
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .create(organization_id(), create_request())
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::SessionTerminationUnsupported
            ))
        ));
    }

    /// A `PendingSeal` target's capability is unknown, so `terminate_sessions: true` is rejected
    /// the same way as a target that confirms it does not support termination — but creating the
    /// config is otherwise allowed.
    #[tokio::test]
    async fn create_rejects_terminate_sessions_on_a_pending_seal_target() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(target_systems_response(vec![
                        PamTargetSystemResponseModel {
                            id: Some(target_system_id().into()),
                            organization_id: Some(organization_id().into()),
                            name: Some("Prod SQL".to_string()),
                            method: Some(ApiTargetSystemMethod::Automatic),
                            status: Some(ApiTargetSystemStatus::PendingSeal),
                            sealed_data: None,
                            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
                            revision_date: Some("2026-01-01T00:00:00Z".to_string()),
                            ..Default::default()
                        },
                    ]))
                })
                .once();
        });

        let result = client(api_client)
            .create(organization_id(), create_request())
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::SessionTerminationUnsupported
            ))
        ));
    }

    /// Creating against an unknown target system must fail with a clear error rather than seal
    /// and send a request the server will also reject.
    #[tokio::test]
    async fn create_fails_when_the_target_system_does_not_exist() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| Ok(target_systems_response(vec![])))
                .once();
        });

        let result = client(api_client)
            .create(organization_id(), create_request())
            .await;

        assert!(matches!(result, Err(RotationError::TargetSystemNotFound)));
    }

    /// A target whose blob fails to unseal cannot be trusted at all, so creating a config against
    /// it is refused outright, regardless of `terminate_sessions`.
    #[tokio::test]
    async fn create_fails_when_the_target_systems_seal_is_invalid() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(target_systems_response(vec![
                        PamTargetSystemResponseModel {
                            id: Some(target_system_id().into()),
                            organization_id: Some(organization_id().into()),
                            name: Some("Prod SQL".to_string()),
                            method: Some(ApiTargetSystemMethod::Automatic),
                            status: Some(ApiTargetSystemStatus::Active),
                            sealed_data: Some("not a sealed blob".to_string()),
                            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
                            revision_date: Some("2026-01-01T00:00:00Z".to_string()),
                            ..Default::default()
                        },
                    ]))
                })
                .once();
        });

        let result = client(api_client)
            .create(organization_id(), create_request())
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::TargetSystemSealInvalid
            ))
        ));
    }

    #[tokio::test]
    async fn update_seals_and_sends_the_request_to_the_requested_config() {
        let organization_key = organization_key();
        let api_client = {
            let target_key = organization_key.clone();
            let config_key = organization_key.clone();
            let response_key = organization_key.clone();
            let existing_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get()
                    .returning(move |_org_id, _id| Ok(sample_detail_response(&existing_key, None)))
                    .once();

                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(target_systems_response(vec![terminable_target_response(
                            &target_key,
                        )]))
                    })
                    .once();

                mock.pam_access_connector_rotation_configs_api
                    .expect_put()
                    .withf(move |org_id, id, request| {
                        if *org_id != Uuid::from(organization_id())
                            || *id != Uuid::from(config_id())
                            || request.rotate_on_access_end != Some(true)
                        {
                            return false;
                        }

                        let store = create_test_crypto_with_user_and_org_key(
                            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                            organization_id(),
                            config_key.clone(),
                        );
                        let mut ctx = store.context_mut();
                        let unsealed = unseal_rotation_config::<KeySlotIds>(
                            &request.sealed_data,
                            &SymmetricKeySlotId::Organization(organization_id()),
                            &mut ctx,
                        )
                        .expect("the blob unseals under the organization key");

                        unsealed.account_identity == "svc_rotation"
                    })
                    .returning(move |_org_id, _id, _request| {
                        Ok(sample_detail_response(&response_key, None))
                    })
                    .once();
            })
        };

        let detail = client_with_org_key(api_client, organization_key)
            .update(organization_id(), config_id(), create_request())
            .await
            .expect("the update succeeds");

        assert_eq!(detail.config.id, config_id());
    }

    #[tokio::test]
    async fn update_rejects_an_invalid_request_before_calling_the_server() {
        let result = client(ApiClient::new_mocked(|_| {}))
            .update(
                organization_id(),
                config_id(),
                RotationConfigCreateRequest {
                    account_identity: String::new(),
                    ..create_request()
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::InvalidAccountIdentity
            ))
        ));
    }

    /// A request naming a different `target_system_id` than the existing config's own plaintext
    /// copy must be refused before sealing or sending anything: both `cipher_id` and
    /// `target_system_id` are fixed at creation. The mock sets no target-system or `put`
    /// expectation, so a call that reached either would fail the test.
    #[tokio::test]
    async fn update_rejects_a_target_system_id_different_from_the_existing_config() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get()
                    .returning(move |_org_id, _id| {
                        // Existing config names `target_system_id()`.
                        Ok(sample_detail_response(&organization_key, None))
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .update(
                organization_id(),
                config_id(),
                RotationConfigCreateRequest {
                    // Request names a different target system.
                    target_system_id: TargetSystemId::new(uuid!(
                        "88888888-8888-8888-8888-888888888888"
                    )),
                    ..create_request()
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::RotationConfigImmutableFieldMismatch
            ))
        ));
    }

    /// Same guard, for `cipher_id` instead of `target_system_id`.
    #[tokio::test]
    async fn update_rejects_a_cipher_id_different_from_the_existing_config() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_configs_api
                    .expect_get()
                    .returning(move |_org_id, _id| {
                        // Existing config names `cipher_id()`.
                        Ok(sample_detail_response(&organization_key, None))
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .update(
                organization_id(),
                config_id(),
                RotationConfigCreateRequest {
                    // Request names a different cipher.
                    cipher_id: CipherId::new(uuid!("99999999-9999-9999-9999-999999999999")),
                    ..create_request()
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::RotationConfigImmutableFieldMismatch
            ))
        ));
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

    /// The unit-returning actions differ only in the route they hit, so each test pins its own.
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
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();
        let config = RotationConfig::from_response(
            organization_id(),
            sample_response(&organization_key),
            &mut ctx,
        )
        .expect("the payload is valid");

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
