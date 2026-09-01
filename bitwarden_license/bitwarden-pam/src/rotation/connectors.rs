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

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Mutex};

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            PamAccessConnectorResponseModelListResponseModel,
            PamAccessConnectorStatus as ApiAccessConnectorStatus, PamRotationJobResponseModel,
            PamRotationJobStatus as ApiRotationJobStatus, PamRotationSource as ApiRotationSource,
            RegisterAccessConnectorResponseModel,
        },
    };
    use bitwarden_core::key_management::{
        SymmetricKeySlotId, create_test_crypto_with_user_and_org_key,
        create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{Decryptable, EncString, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::rotation::{
        models::{RotationJobStatus, RotationSource},
        registration::ConnectorToken,
        validate::RotationValidationError,
    };

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn connector_id() -> AccessConnectorId {
        AccessConnectorId::new(uuid!("22222222-2222-2222-2222-222222222222"))
    }

    fn target_system_id() -> TargetSystemId {
        TargetSystemId::new(uuid!("33333333-3333-3333-3333-333333333333"))
    }

    fn job_id() -> Uuid {
        uuid!("44444444-4444-4444-4444-444444444444")
    }

    fn api_key_id() -> Uuid {
        uuid!("55555555-5555-5555-5555-555555555555")
    }

    fn client(api_client: ApiClient) -> AccessConnectorsClient {
        client_with_org_key(
            api_client,
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
        )
    }

    fn client_with_org_key(
        api_client: ApiClient,
        organization_key: SymmetricCryptoKey,
    ) -> AccessConnectorsClient {
        AccessConnectorsClient {
            key_store: create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key,
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    /// A payload with every optional field populated, so a test that clears one is unambiguous
    /// about which field it is exercising.
    fn sample_response() -> PamAccessConnectorResponseModel {
        PamAccessConnectorResponseModel {
            id: Some(connector_id().into()),
            organization_id: Some(organization_id().into()),
            name: Some("Prod connector".to_string()),
            status: Some(ApiAccessConnectorStatus::Enabled),
            is_connected: Some(true),
            last_heartbeat_at: Some("2026-02-01T12:30:00Z".to_string()),
            assigned_target_system_ids: Some(vec![target_system_id().into()]),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            revision_date: Some("2026-01-15T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    /// The same connector as [`sample_response`], as the detail route returns it: the connector's
    /// own fields flattened onto the payload, plus its recent jobs.
    fn sample_detail_response(
        jobs: Option<Vec<PamRotationJobResponseModel>>,
    ) -> PamAccessConnectorDetailResponseModel {
        let connector = sample_response();
        PamAccessConnectorDetailResponseModel {
            object: connector.object,
            id: connector.id,
            organization_id: connector.organization_id,
            name: connector.name,
            status: connector.status,
            is_connected: connector.is_connected,
            last_heartbeat_at: connector.last_heartbeat_at,
            assigned_target_system_ids: connector.assigned_target_system_ids,
            creation_date: connector.creation_date,
            revision_date: connector.revision_date,
            jobs,
        }
    }

    fn sample_job(id: Uuid) -> PamRotationJobResponseModel {
        PamRotationJobResponseModel {
            id: Some(id),
            rotation_config_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            source: Some(ApiRotationSource::Scheduled),
            status: Some(ApiRotationJobStatus::Succeeded),
            creation_date: Some("2026-01-10T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn registration_response() -> RegisterAccessConnectorResponseModel {
        RegisterAccessConnectorResponseModel {
            id: Some(connector_id().into()),
            organization_id: Some(organization_id().into()),
            name: Some("Prod connector".to_string()),
            status: Some(ApiAccessConnectorStatus::Enabled),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            api_key_id: Some(api_key_id()),
            client_secret: Some("client-secret-value".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn a_full_payload_maps_every_field() {
        let connector = AccessConnector::try_from(sample_response()).expect("the payload is valid");

        assert_eq!(connector.id, connector_id());
        assert_eq!(connector.organization_id, organization_id());
        assert_eq!(connector.name, "Prod connector");
        assert_eq!(connector.status, AccessConnectorStatus::Enabled);
        assert!(connector.is_connected);
        assert_eq!(
            connector.last_heartbeat_at,
            Some("2026-02-01T12:30:00Z".parse().expect("a valid timestamp"))
        );
        assert_eq!(connector.assigned_target_system_ids, [target_system_id()]);
        assert_eq!(
            connector.creation_date,
            "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            connector.revision_date,
            "2026-01-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    /// A connector that has never phoned home reports no heartbeat and no assignments. Neither is
    /// an error, and `is_connected` has to read as *not connected* rather than defaulting true.
    #[test]
    fn a_connector_that_has_never_connected_maps_to_disconnected_with_no_heartbeat() {
        let response = PamAccessConnectorResponseModel {
            is_connected: None,
            last_heartbeat_at: None,
            assigned_target_system_ids: None,
            ..sample_response()
        };

        let connector = AccessConnector::try_from(response).expect("the payload is valid");

        assert!(!connector.is_connected);
        assert_eq!(connector.last_heartbeat_at, None);
        assert!(connector.assigned_target_system_ids.is_empty());
    }

    #[test]
    fn a_missing_required_field_is_reported_rather_than_defaulted() {
        for response in [
            PamAccessConnectorResponseModel {
                id: None,
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                organization_id: None,
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                name: None,
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                status: None,
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                creation_date: None,
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                revision_date: None,
                ..sample_response()
            },
        ] {
            assert!(matches!(
                AccessConnector::try_from(response.clone()),
                Err(RotationError::MissingField(_))
            ));
        }
    }

    #[test]
    fn an_unparseable_date_is_reported() {
        for response in [
            PamAccessConnectorResponseModel {
                creation_date: Some("not a date".to_string()),
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                revision_date: Some("not a date".to_string()),
                ..sample_response()
            },
            PamAccessConnectorResponseModel {
                last_heartbeat_at: Some("not a date".to_string()),
                ..sample_response()
            },
        ] {
            assert!(matches!(
                AccessConnector::try_from(response),
                Err(RotationError::Chrono(_))
            ));
        }
    }

    /// A newer server naming a status this version does not model must not fail the whole list -
    /// see the forward-compatibility note in the module docs.
    #[test]
    fn an_unrecognized_status_degrades_to_unknown() {
        let response = PamAccessConnectorResponseModel {
            status: Some(ApiAccessConnectorStatus::__Unknown(99)),
            ..sample_response()
        };

        let connector = AccessConnector::try_from(response).expect("an unknown status still maps");

        assert_eq!(connector.status, AccessConnectorStatus::Unknown);
    }

    /// The detail conversion hand-copies the connector's nine fields out of the flattened payload,
    /// so a field dropped there would silently read as absent. Comparing against the list
    /// conversion of the same connector pins all nine at once.
    #[test]
    fn the_detail_payload_yields_the_same_connector_as_the_list_payload() {
        let detail =
            AccessConnectorDetail::try_from(sample_detail_response(Some(vec![sample_job(
                job_id(),
            )])))
            .expect("the payload is valid");

        assert_eq!(
            detail.connector,
            AccessConnector::try_from(sample_response()).expect("the payload is valid")
        );
    }

    #[test]
    fn detail_jobs_keep_the_order_the_server_sent() {
        let second = uuid!("77777777-7777-7777-7777-777777777777");
        let detail = AccessConnectorDetail::try_from(sample_detail_response(Some(vec![
            sample_job(job_id()),
            sample_job(second),
        ])))
        .expect("the payload is valid");

        let ids: Vec<Uuid> = detail.jobs.iter().map(|job| job.id.into()).collect();
        assert_eq!(ids, [job_id(), second]);
        assert_eq!(detail.jobs[0].source, RotationSource::Scheduled);
        assert_eq!(detail.jobs[0].status, RotationJobStatus::Succeeded);
    }

    /// A connector that has never been dispatched work is not an error - it has no jobs.
    #[test]
    fn a_detail_payload_without_jobs_has_no_jobs() {
        let detail =
            AccessConnectorDetail::try_from(sample_detail_response(None)).expect("no jobs is fine");

        assert!(detail.jobs.is_empty());
    }

    #[test]
    fn a_malformed_job_fails_the_whole_detail() {
        let malformed = PamRotationJobResponseModel {
            id: None,
            ..sample_job(job_id())
        };

        let result = AccessConnectorDetail::try_from(sample_detail_response(Some(vec![malformed])));

        assert!(matches!(result, Err(RotationError::MissingField(_))));
    }

    #[tokio::test]
    async fn list_maps_the_organizations_connectors() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_get_all()
                .withf(|org_id| *org_id == Uuid::from(organization_id()))
                .returning(move |_org_id| {
                    Ok(PamAccessConnectorResponseModelListResponseModel {
                        data: Some(vec![sample_response()]),
                        ..Default::default()
                    })
                })
                .once();
        });

        let connectors = client(api_client)
            .list(organization_id())
            .await
            .expect("the list succeeds");

        assert_eq!(connectors.len(), 1);
        assert_eq!(connectors[0].id, connector_id());
    }

    #[tokio::test]
    async fn an_organization_with_no_connectors_lists_empty() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamAccessConnectorResponseModelListResponseModel::default())
                })
                .once();
        });

        let connectors = client(api_client)
            .list(organization_id())
            .await
            .expect("an absent list is not an error");

        assert!(connectors.is_empty());
    }

    #[tokio::test]
    async fn list_fails_if_any_connector_is_malformed() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamAccessConnectorResponseModelListResponseModel {
                        data: Some(vec![
                            sample_response(),
                            PamAccessConnectorResponseModel {
                                id: None,
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
            mock.pam_access_connectors_api
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
    async fn get_reads_the_requested_connector_with_its_jobs() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_get()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(connector_id())
                })
                .returning(move |_org_id, _id| {
                    Ok(sample_detail_response(Some(vec![sample_job(job_id())])))
                })
                .once();
        });

        let detail = client(api_client)
            .get(organization_id(), connector_id())
            .await
            .expect("the read succeeds");

        assert_eq!(detail.connector.id, connector_id());
        assert_eq!(detail.jobs.len(), 1);
    }

    #[tokio::test]
    async fn get_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
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

        let result = client(api_client)
            .get(organization_id(), connector_id())
            .await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    /// The whole point of `register`: the connector must be able to recover the organization key
    /// from the token it is handed plus the `encryptedPayload` the server stored. This walks that
    /// path end to end through the public method - the token comes from the response, the payload
    /// from the request that was actually sent - so a mismatch between the two halves fails here.
    #[tokio::test]
    async fn register_returns_a_token_that_recovers_the_organization_key() {
        let organization_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let sent_payload = Arc::new(Mutex::new(None));

        let captured = sent_payload.clone();
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_post()
                .withf(|org_id, request| {
                    *org_id == Uuid::from(organization_id()) && request.name == "Prod connector"
                })
                .returning(move |_org_id, request| {
                    *captured.lock().expect("the lock is not poisoned") =
                        Some(request.encrypted_payload);
                    Ok(registration_response())
                })
                .once();
        });

        let registered = client_with_org_key(api_client, organization_key.clone())
            .register(organization_id(), "Prod connector".to_string())
            .await
            .expect("registration succeeds");

        assert_eq!(registered.id, connector_id());
        assert_eq!(registered.organization_id, organization_id());
        assert_eq!(registered.name, "Prod connector");
        assert_eq!(registered.status, AccessConnectorStatus::Enabled);

        // Everything below is what a connector does with the token it was provisioned.
        let token = ConnectorToken::from_str(&registered.token).expect("the token parses");
        assert_eq!(token.api_key_id, api_key_id());
        assert_eq!(token.client_secret, "client-secret-value");

        let payload: EncString = sent_payload
            .lock()
            .expect("the lock is not poisoned")
            .clone()
            .expect("the request carried an encrypted payload")
            .parse()
            .expect("the payload is an EncString");

        let connector_store = create_test_crypto_with_user_key(token.encryption_key);
        let decrypted: String = payload
            .decrypt(&mut connector_store.context(), SymmetricKeySlotId::User)
            .expect("the key derived from the token decrypts the payload");
        let recovered: serde_json::Value =
            serde_json::from_str(&decrypted).expect("the payload is JSON");

        assert_eq!(
            recovered["encryptionKey"].as_str(),
            Some(organization_key.to_base64().to_string().as_str()),
            "the connector must recover the organization key verbatim"
        );
    }

    /// The token is unrecoverable, so the caller has to be able to show the operator which
    /// connector it belongs to even if the server echoes no name back.
    #[tokio::test]
    async fn register_falls_back_to_the_requested_name_when_the_server_omits_it() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_post()
                .returning(move |_org_id, _request| {
                    Ok(RegisterAccessConnectorResponseModel {
                        name: None,
                        ..registration_response()
                    })
                })
                .once();
        });

        let registered = client(api_client)
            .register(organization_id(), "Prod connector".to_string())
            .await
            .expect("registration succeeds");

        assert_eq!(registered.name, "Prod connector");
    }

    /// A registration that cannot produce a usable token must not leave a registered connector
    /// behind - the operator would have no way to provision it and no way to recover the secret.
    /// The mock has no expectations, so any call to the server fails the test.
    #[tokio::test]
    async fn register_rejects_an_invalid_name_before_calling_the_server() {
        for name in ["", "   ", &"a".repeat(201)] {
            let result = client(ApiClient::new_mocked(|_| {}))
                .register(organization_id(), name.to_string())
                .await;

            assert!(
                matches!(
                    result,
                    Err(RotationError::Validation(
                        RotationValidationError::InvalidName
                    ))
                ),
                "for {name:?}"
            );
        }
    }

    /// Same obligation as an invalid name, for the other failure that precedes the call: without
    /// the organization key there is nothing to wrap into the token.
    #[tokio::test]
    async fn register_without_the_organization_key_never_reaches_the_server() {
        let client = AccessConnectorsClient {
            // A store with a user key but no organization key - the caller is not a member.
            key_store: create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
        };

        let result = client
            .register(organization_id(), "Prod connector".to_string())
            .await;

        assert!(matches!(result, Err(RotationError::MissingOrganizationKey)));
    }

    /// A token missing either half cannot authenticate, so a response without them has to fail
    /// rather than hand back a string that looks like a credential.
    #[tokio::test]
    async fn register_fails_when_the_response_cannot_complete_the_token() {
        for response in [
            RegisterAccessConnectorResponseModel {
                api_key_id: None,
                ..registration_response()
            },
            RegisterAccessConnectorResponseModel {
                client_secret: None,
                ..registration_response()
            },
        ] {
            let api_client = ApiClient::new_mocked(move |mock| {
                mock.pam_access_connectors_api
                    .expect_post()
                    .returning(move |_org_id, _request| Ok(response.clone()))
                    .once();
            });

            let result = client(api_client)
                .register(organization_id(), "Prod connector".to_string())
                .await;

            assert!(matches!(result, Err(RotationError::MissingField(_))));
        }
    }

    #[tokio::test]
    async fn enable_targets_the_requested_connector() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_enable()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(connector_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .enable(organization_id(), connector_id())
            .await
            .expect("enabling succeeds");
    }

    #[tokio::test]
    async fn disable_targets_the_requested_connector() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_disable()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(connector_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .disable(organization_id(), connector_id())
            .await
            .expect("disabling succeeds");
    }

    #[tokio::test]
    async fn delete_targets_the_requested_connector() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_delete()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id()) && *id == Uuid::from(connector_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .delete(organization_id(), connector_id())
            .await
            .expect("deleting succeeds");
    }

    #[tokio::test]
    async fn delete_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_delete()
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

        let result = client(api_client)
            .delete(organization_id(), connector_id())
            .await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    #[tokio::test]
    async fn assign_target_sends_the_target_system_in_the_body() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_assign_target()
                .withf(|org_id, id, request| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(connector_id())
                        && request.target_system_id == Uuid::from(target_system_id())
                })
                .returning(move |_org_id, _id, _request| Ok(()))
                .once();
        });

        client(api_client)
            .assign_target(organization_id(), connector_id(), target_system_id())
            .await
            .expect("assigning succeeds");
    }

    /// `unassign_target` puts the target system in the path rather than a body, so it takes three
    /// same-typed identifiers in a row - transposing two would still compile.
    #[tokio::test]
    async fn unassign_target_sends_the_identifiers_in_the_right_order() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connectors_api
                .expect_unassign_target()
                .withf(|org_id, id, target_system_id_arg| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(connector_id())
                        && *target_system_id_arg == Uuid::from(target_system_id())
                })
                .returning(move |_org_id, _id, _target_system_id| Ok(()))
                .once();
        });

        client(api_client)
            .unassign_target(organization_id(), connector_id(), target_system_id())
            .await
            .expect("unassigning succeeds");
    }
}
