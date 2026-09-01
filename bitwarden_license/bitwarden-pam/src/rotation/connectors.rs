use std::sync::Arc;

use bitwarden_api_api::models::{
    AssignAccessConnectorTargetRequestModel, PamAccessConnectorDetailResponseModel,
    PamAccessConnectorResponseModel, RegisterAccessConnectorRequestModel,
};
use bitwarden_core::{
    FromClient, OrganizationId, client::ApiConfigurations, key_management::KeySlotIds, require,
};
use bitwarden_crypto::KeyStore;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    error::RotationError,
    models::{AccessConnectorStatus, RotationJob},
    validate::validate_name,
};
use crate::{AccessConnectorId, TargetSystemId};

/// An access connector: the unattended agent that performs credential rotations for an
/// organization.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessConnector {
    /// The connector's unique identifier.
    pub id: AccessConnectorId,
    /// The organization this connector belongs to.
    pub organization_id: OrganizationId,
    /// Display name.
    ///
    /// Stored as a plaintext server column, not vault data, and audit rows snapshot it at write
    /// time - so it is visible to the server and should not be used to carry anything sensitive.
    pub name: String,
    /// Lifecycle state.
    pub status: AccessConnectorStatus,
    /// Whether the connector is currently connected. Reflects the server's presence check, so it
    /// can lag reality by up to one heartbeat interval.
    pub is_connected: bool,
    /// The last heartbeat the server recorded (UTC), or `None` if it has never connected.
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    /// The target systems this connector may rotate.
    pub assigned_target_system_ids: Vec<TargetSystemId>,
    /// When the connector was registered (UTC).
    pub creation_date: DateTime<Utc>,
    /// When the connector was last modified (UTC).
    pub revision_date: DateTime<Utc>,
}

impl TryFrom<PamAccessConnectorResponseModel> for AccessConnector {
    type Error = RotationError;

    fn try_from(response: PamAccessConnectorResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: AccessConnectorId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            name: require!(response.name),
            status: require!(response.status).into(),
            is_connected: response.is_connected.unwrap_or(false),
            last_heartbeat_at: response
                .last_heartbeat_at
                .map(|date| date.parse())
                .transpose()?,
            assigned_target_system_ids: response
                .assigned_target_system_ids
                .unwrap_or_default()
                .into_iter()
                .map(TargetSystemId::new)
                .collect(),
            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}

/// A connector together with its recent rotation activity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessConnectorDetail {
    /// The connector itself.
    #[serde(flatten)]
    pub connector: AccessConnector,
    /// The jobs this connector has worked, newest first, carrying the attempts it recorded.
    ///
    /// The server caps how many it returns, so this is recent activity rather than the connector's
    /// whole history.
    pub jobs: Vec<RotationJob>,
}

impl TryFrom<PamAccessConnectorDetailResponseModel> for AccessConnectorDetail {
    type Error = RotationError;

    fn try_from(response: PamAccessConnectorDetailResponseModel) -> Result<Self, Self::Error> {
        let jobs = response
            .jobs
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(RotationJob::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        // The server flattens the connector's own fields onto the detail payload.
        let connector = AccessConnector::try_from(PamAccessConnectorResponseModel {
            object: response.object,
            id: response.id,
            organization_id: response.organization_id,
            name: response.name,
            status: response.status,
            is_connected: response.is_connected,
            last_heartbeat_at: response.last_heartbeat_at,
            assigned_target_system_ids: response.assigned_target_system_ids,
            creation_date: response.creation_date,
            revision_date: response.revision_date,
        })?;

        Ok(Self { connector, jobs })
    }
}

/// The result of registering a connector, including its one-time token.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessConnectorRegistrationResponse {
    /// The newly registered connector's unique identifier.
    pub id: AccessConnectorId,
    /// The organization the connector was registered in.
    pub organization_id: OrganizationId,
    /// The connector's display name.
    pub name: String,
    /// Lifecycle state. A freshly registered connector is
    /// [`Enabled`](AccessConnectorStatus::Enabled).
    pub status: AccessConnectorStatus,
    /// When the connector was registered (UTC).
    pub creation_date: DateTime<Utc>,
    /// The credential the operator provisions into the connector's configuration.
    ///
    /// Format: `0.access-connector.<api-key-id>.<client-secret>:<b64-seed>`.
    ///
    /// **Returned exactly once and unrecoverable.** The server keeps only a hash of the client
    /// secret, and the seed exists nowhere else. Show it for the operator to copy, deliver it
    /// out-of-band, and do not persist or log it. If it is lost, delete the connector and register
    /// again.
    pub token: String,
}

/// Client for PAM access connector operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct AccessConnectorsClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AccessConnectorsClient {
    /// Lists the organization's access connectors.
    pub async fn list(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<AccessConnector>, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connectors_api()
            .get_all(organization_id.into())
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessConnector::try_from)
            .collect()
    }

    /// Reads one connector with its recent rotation activity.
    pub async fn get(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
    ) -> Result<AccessConnectorDetail, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connectors_api()
            .get(organization_id.into(), id.into())
            .await?;

        AccessConnectorDetail::try_from(response)
    }

    /// Registers a connector and returns its one-time token.
    ///
    /// The token is the only copy - see [`AccessConnectorRegistrationResponse::token`] for the
    /// handling obligation, and the [`registration`](super::registration) module docs for what
    /// it contains and why.
    pub async fn register(
        &self,
        organization_id: OrganizationId,
        name: String,
    ) -> Result<AccessConnectorRegistrationResponse, RotationError> {
        validate_name(&name)?;

        // Derived before the call so a key-store problem fails without leaving a registered
        // connector the caller has no token for.
        let secrets = self.registration_secrets(organization_id)?;

        let response = self
            .api_configurations
            .api_client
            .pam_access_connectors_api()
            .post(
                organization_id.into(),
                RegisterAccessConnectorRequestModel {
                    name: name.clone(),
                    encrypted_payload: secrets.encrypted_payload.to_string(),
                    key: secrets.key.to_string(),
                },
            )
            .await?;

        let api_key_id = require!(response.api_key_id);
        let client_secret = require!(response.client_secret);

        Ok(AccessConnectorRegistrationResponse {
            id: AccessConnectorId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            name: response.name.unwrap_or(name),
            status: require!(response.status).into(),
            creation_date: require!(response.creation_date).parse()?,
            token: secrets.into_token(api_key_id, &client_secret),
        })
    }

    /// Re-enables a disabled connector so it can authenticate and claim jobs again.
    pub async fn enable(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connectors_api()
            .enable(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Disables a connector: it stops claiming new jobs and its running jobs are released.
    ///
    /// Reversible - the credential is retained, so [`enable`](AccessConnectorsClient::enable) puts
    /// it back to work. To retire a connector for good, use
    /// [`delete`](AccessConnectorsClient::delete).
    pub async fn disable(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connectors_api()
            .disable(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Permanently deletes a connector and invalidates its credential.
    ///
    /// The connector held the plaintext organization key in memory, so deletion alone does not
    /// undo a compromise: rotating the organization key is the remediation if one is suspected.
    pub async fn delete(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connectors_api()
            .delete(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Assigns a target system to a connector, so it may rotate credentials against that target.
    pub async fn assign_target(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
        target_system_id: TargetSystemId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connectors_api()
            .assign_target(
                organization_id.into(),
                id.into(),
                AssignAccessConnectorTargetRequestModel {
                    target_system_id: target_system_id.into(),
                },
            )
            .await?;

        Ok(())
    }

    /// Removes a target-system assignment from a connector.
    pub async fn unassign_target(
        &self,
        organization_id: OrganizationId,
        id: AccessConnectorId,
        target_system_id: TargetSystemId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connectors_api()
            .unassign_target(organization_id.into(), id.into(), target_system_id.into())
            .await?;

        Ok(())
    }
}
