use std::sync::Arc;

use bitwarden_api_api::models::{
    PamTargetSystemResponseModel, RegisterTargetSystemRequestModel, UpdateTargetSystemRequestModel,
};
use bitwarden_core::{FromClient, OrganizationId, client::ApiConfigurations, require};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    error::RotationError,
    models::{PasswordPolicy, TargetSystemKind, TargetSystemMethod, TargetSystemStatus},
    validate::{validate_target_system_create, validate_target_system_update},
};
use crate::TargetSystemId;

/// A target system a credential can be rotated against.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct TargetSystem {
    /// The target system's unique identifier.
    pub id: TargetSystemId,
    /// The organization this target system belongs to.
    pub organization_id: OrganizationId,
    /// Display name. Plaintext organization configuration, not vault data.
    pub name: String,
    /// How credentials are rotated for this target.
    pub method: TargetSystemMethod,
    /// The integration behind the target. `None` when the method is
    /// [`Manual`](TargetSystemMethod::Manual) - there is no integration to name.
    pub kind: Option<TargetSystemKind>,
    /// Lifecycle state.
    pub status: TargetSystemStatus,
    /// Constraints applied when generating a rotated credential. `None` when no policy has been
    /// configured.
    pub password_policy: Option<PasswordPolicy>,
    /// Whether the integration can terminate the account's sessions after rotating. `None` when
    /// the method is Manual or the server has not surfaced the capability.
    pub supports_session_termination: Option<bool>,
    /// When the target system was created (UTC).
    pub creation_date: DateTime<Utc>,
    /// When the target system was last modified (UTC).
    pub revision_date: DateTime<Utc>,
}

impl TryFrom<PamTargetSystemResponseModel> for TargetSystem {
    type Error = RotationError;

    fn try_from(response: PamTargetSystemResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: TargetSystemId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            name: require!(response.name),
            method: require!(response.method).into(),
            kind: response.kind.map(Into::into),
            status: require!(response.status).into(),
            password_policy: response.password_policy.map(|policy| (*policy).into()),
            supports_session_termination: response.supports_session_termination,
            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}

/// Request to create a target system.
///
/// Modeled as a discriminated union rather than a struct of optional fields because the two methods
/// take genuinely different input: an automatic target needs an integration and a
/// session-termination capability, a manual one has neither. Encoding that in the type stops a
/// caller from constructing the combination the server rejects.
///
/// Serializes with a `method` discriminant matching the server's own, e.g.
/// `{"method":"manual","name":"...","passwordPolicy":{...}}`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum TargetSystemCreateRequest {
    /// A connector rotates the credential by writing it into the target system.
    #[serde(rename_all = "camelCase")]
    Automatic {
        /// Display name.
        name: String,
        /// The integration that performs the rotation.
        kind: TargetSystemKind,
        /// Constraints the connector generates the new credential under.
        password_policy: PasswordPolicy,
        /// Whether the integration can terminate the account's sessions after rotating.
        supports_session_termination: bool,
    },
    /// An operator rotates the credential out of band and records that they did.
    #[serde(rename_all = "camelCase")]
    Manual {
        /// Display name.
        name: String,
        /// The rules the operator is expected to follow when rotating by hand. Nothing enforces
        /// them - no connector runs a manual rotation.
        password_policy: PasswordPolicy,
    },
}

impl TargetSystemCreateRequest {
    /// The display name, whichever method this request carries.
    pub fn name(&self) -> &str {
        match self {
            Self::Automatic { name, .. } | Self::Manual { name, .. } => name,
        }
    }

    /// The password policy, whichever method this request carries.
    pub fn password_policy(&self) -> &PasswordPolicy {
        match self {
            Self::Automatic {
                password_policy, ..
            }
            | Self::Manual {
                password_policy, ..
            } => password_policy,
        }
    }
}

impl TryFrom<TargetSystemCreateRequest> for RegisterTargetSystemRequestModel {
    type Error = RotationError;

    fn try_from(request: TargetSystemCreateRequest) -> Result<Self, Self::Error> {
        Ok(match request {
            TargetSystemCreateRequest::Automatic {
                name,
                kind,
                password_policy,
                supports_session_termination,
            } => Self {
                name,
                method: TargetSystemMethod::Automatic.try_into()?,
                kind: Some(kind.try_into()?),
                password_policy: Some(Box::new(password_policy.into())),
                supports_session_termination: Some(supports_session_termination),
            },
            TargetSystemCreateRequest::Manual {
                name,
                password_policy,
            } => Self {
                name,
                method: TargetSystemMethod::Manual.try_into()?,
                // A manual target has no integration and no session to terminate. Sending either
                // would have the server store a capability nothing can act on.
                kind: None,
                password_policy: Some(Box::new(password_policy.into())),
                supports_session_termination: None,
            },
        })
    }
}

/// Request to update an existing target system.
///
/// The name and the policy travel together because the server takes them in one `PUT`; a caller
/// changing only one still has to send the other's current value. Neither the method nor the
/// integration kind can be changed after creation - the server derives rotation behaviour from
/// them, and configs already reference the target.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct TargetSystemUpdateRequest {
    /// Display name.
    pub name: String,
    /// Constraints applied when generating a rotated credential.
    pub password_policy: PasswordPolicy,
    /// Whether the integration can terminate the account's sessions after rotating.
    ///
    /// Applies only to automatic targets; a manual target has no session to terminate, so the
    /// server ignores it. Withdrawing the capability can be *rejected* when live configs depend on
    /// it, so a caller should warn before submitting a change from `true` to `false`.
    pub supports_session_termination: bool,
}

impl From<TargetSystemUpdateRequest> for UpdateTargetSystemRequestModel {
    fn from(request: TargetSystemUpdateRequest) -> Self {
        Self {
            name: request.name,
            password_policy: Some(Box::new(request.password_policy.into())),
            supports_session_termination: Some(request.supports_session_termination),
        }
    }
}

/// Client for PAM rotation target-system operations.
///
/// A target can be quieted or removed, and the two are not interchangeable:
/// [`disable`](TargetSystemsClient::disable) is reversible and leaves the target's configs intact,
/// while [`delete`](TargetSystemsClient::delete) is permanent and the server refuses it while any
/// config still names the target.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct TargetSystemsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl TargetSystemsClient {
    /// Lists the organization's target systems.
    pub async fn list(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<TargetSystem>, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .get_all(organization_id.into())
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(TargetSystem::try_from)
            .collect()
    }

    /// Validates and creates a target system.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        request: TargetSystemCreateRequest,
    ) -> Result<TargetSystem, RotationError> {
        validate_target_system_create(&request)?;

        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .post(organization_id.into(), request.try_into()?)
            .await?;

        TargetSystem::try_from(response)
    }

    /// Validates and updates a target system's name, policy, and session-termination capability.
    ///
    /// The server answers with no content, so a caller that renders the result should re-read
    /// through [`list`](TargetSystemsClient::list) rather than assume the request body is now the
    /// stored state.
    pub async fn update(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
        request: TargetSystemUpdateRequest,
    ) -> Result<(), RotationError> {
        validate_target_system_update(&request)?;

        self.api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .put(organization_id.into(), id.into(), request.into())
            .await?;

        Ok(())
    }

    /// Returns a disabled target system to service, so new rotation jobs are dispatched for it
    /// again.
    pub async fn enable(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .enable(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Stops new rotation jobs being dispatched for a target system. Jobs already in flight run to
    /// completion.
    pub async fn disable(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .disable(organization_id.into(), id.into())
            .await?;

        Ok(())
    }

    /// Permanently deletes a target system.
    ///
    /// The server refuses this while any rotation config still names the target: deleting it would
    /// leave that config, and the credential it manages, pointing at nothing. Delete those configs
    /// first, which is also what releases each cipher. The connector-to-target assignments are the
    /// opposite case and go with it - an assignment is only that edge, and means nothing once the
    /// target is gone. No rotation can be in flight to be torn up, since a job belongs to a config
    /// on this target and a surviving config blocks the delete outright.
    ///
    /// Deliberately narrower than [`disable`](TargetSystemsClient::disable), which stops new
    /// rotations while the target and its configs stay intact. Disable is for a target that is
    /// merely unavailable; delete is for one that has left the estate.
    pub async fn delete(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
    ) -> Result<(), RotationError> {
        self.api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .delete(organization_id.into(), id.into())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            PamPasswordPolicyResponseModel, PamTargetSystemKind as ApiTargetSystemKind,
            PamTargetSystemMethod as ApiTargetSystemMethod,
            PamTargetSystemResponseModelListResponseModel,
            PamTargetSystemStatus as ApiTargetSystemStatus,
        },
    };
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::rotation::validate::RotationValidationError;

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn target_system_id() -> TargetSystemId {
        TargetSystemId::new(uuid!("22222222-2222-2222-2222-222222222222"))
    }

    fn client(api_client: ApiClient) -> TargetSystemsClient {
        TargetSystemsClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 14,
            max_length: 64,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: false,
        }
    }

    /// An automatic target with every optional field populated, so a test that clears one is
    /// unambiguous about which field it is exercising.
    fn sample_response() -> PamTargetSystemResponseModel {
        PamTargetSystemResponseModel {
            id: Some(target_system_id().into()),
            organization_id: Some(organization_id().into()),
            name: Some("Prod SQL".to_string()),
            method: Some(ApiTargetSystemMethod::Automatic),
            kind: Some(ApiTargetSystemKind::Mssql),
            password_policy: Some(Box::new(PamPasswordPolicyResponseModel {
                min_length: Some(14),
                max_length: Some(64),
                include_uppercase: Some(true),
                include_lowercase: Some(true),
                include_digits: Some(true),
                include_symbols: Some(false),
            })),
            supports_session_termination: Some(true),
            status: Some(ApiTargetSystemStatus::Active),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            revision_date: Some("2026-01-15T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn automatic_create_request() -> TargetSystemCreateRequest {
        TargetSystemCreateRequest::Automatic {
            name: "Prod SQL".to_string(),
            kind: TargetSystemKind::Mssql,
            password_policy: policy(),
            supports_session_termination: true,
        }
    }

    fn manual_create_request() -> TargetSystemCreateRequest {
        TargetSystemCreateRequest::Manual {
            name: "Legacy mainframe".to_string(),
            password_policy: policy(),
        }
    }

    fn update_request() -> TargetSystemUpdateRequest {
        TargetSystemUpdateRequest {
            name: "Prod SQL".to_string(),
            password_policy: policy(),
            supports_session_termination: true,
        }
    }

    #[test]
    fn a_full_payload_maps_every_field() {
        let target = TargetSystem::try_from(sample_response()).expect("the payload is valid");

        assert_eq!(target.id, target_system_id());
        assert_eq!(target.organization_id, organization_id());
        assert_eq!(target.name, "Prod SQL");
        assert_eq!(target.method, TargetSystemMethod::Automatic);
        assert_eq!(target.kind, Some(TargetSystemKind::Mssql));
        assert_eq!(target.status, TargetSystemStatus::Active);
        assert_eq!(target.password_policy, Some(policy()));
        assert_eq!(target.supports_session_termination, Some(true));
        assert_eq!(
            target.creation_date,
            "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            target.revision_date,
            "2026-01-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    /// A manual target has no integration and no session to terminate, so those arrive absent
    /// rather than as a falsy value that would read as "an integration that cannot do it".
    #[test]
    fn a_manual_target_has_no_integration_and_no_session_capability() {
        let response = PamTargetSystemResponseModel {
            method: Some(ApiTargetSystemMethod::Manual),
            kind: None,
            supports_session_termination: None,
            password_policy: None,
            ..sample_response()
        };

        let target = TargetSystem::try_from(response).expect("the payload is valid");

        assert_eq!(target.method, TargetSystemMethod::Manual);
        assert_eq!(target.kind, None);
        assert_eq!(target.supports_session_termination, None);
        assert_eq!(target.password_policy, None);
    }

    /// A policy the server sent with flags omitted must read as those classes being *off*. Reading
    /// them as on would show an operator a policy the connector will not generate under.
    #[test]
    fn omitted_policy_flags_read_as_disabled() {
        let response = PamTargetSystemResponseModel {
            password_policy: Some(Box::new(PamPasswordPolicyResponseModel::default())),
            ..sample_response()
        };

        let target = TargetSystem::try_from(response).expect("the payload is valid");

        assert_eq!(
            target.password_policy,
            Some(PasswordPolicy {
                min_length: 0,
                max_length: 0,
                include_uppercase: false,
                include_lowercase: false,
                include_digits: false,
                include_symbols: false,
            })
        );
    }

    #[test]
    fn a_missing_required_field_is_reported_rather_than_defaulted() {
        for response in [
            PamTargetSystemResponseModel {
                id: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                organization_id: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                name: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                method: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                status: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                creation_date: None,
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                revision_date: None,
                ..sample_response()
            },
        ] {
            assert!(matches!(
                TargetSystem::try_from(response),
                Err(RotationError::MissingField(_))
            ));
        }
    }

    #[test]
    fn an_unparseable_date_is_reported() {
        for response in [
            PamTargetSystemResponseModel {
                creation_date: Some("not a date".to_string()),
                ..sample_response()
            },
            PamTargetSystemResponseModel {
                revision_date: Some("not a date".to_string()),
                ..sample_response()
            },
        ] {
            assert!(matches!(
                TargetSystem::try_from(response),
                Err(RotationError::Chrono(_))
            ));
        }
    }

    /// A newer server naming a method, kind, or status this version does not model must degrade
    /// rather than fail the whole list.
    #[test]
    fn unrecognized_enum_values_degrade_to_unknown() {
        let response = PamTargetSystemResponseModel {
            method: Some(ApiTargetSystemMethod::__Unknown(9)),
            kind: Some(ApiTargetSystemKind::__Unknown(9)),
            status: Some(ApiTargetSystemStatus::__Unknown(9)),
            ..sample_response()
        };

        let target = TargetSystem::try_from(response).expect("unknown values still map");

        assert_eq!(target.method, TargetSystemMethod::Unknown);
        assert_eq!(target.kind, Some(TargetSystemKind::Unknown));
        assert_eq!(target.status, TargetSystemStatus::Unknown);
    }

    #[test]
    fn an_automatic_create_request_carries_the_integration_and_the_capability() {
        let model = RegisterTargetSystemRequestModel::try_from(automatic_create_request())
            .expect("the request is representable");

        assert_eq!(model.name, "Prod SQL");
        assert_eq!(model.method, ApiTargetSystemMethod::Automatic);
        assert_eq!(model.kind, Some(ApiTargetSystemKind::Mssql));
        assert_eq!(model.supports_session_termination, Some(true));
        let sent_policy = *model.password_policy.expect("a policy is sent");
        assert_eq!(sent_policy.min_length, 14);
        assert_eq!(sent_policy.max_length, 64);
        assert_eq!(sent_policy.include_symbols, Some(false));
    }

    /// A manual target must send neither field. Sending `Some(false)` for the capability would have
    /// the server store a session-termination answer for a rotation no connector performs.
    #[test]
    fn a_manual_create_request_sends_no_integration_and_no_capability() {
        let model = RegisterTargetSystemRequestModel::try_from(manual_create_request())
            .expect("the request is representable");

        assert_eq!(model.method, ApiTargetSystemMethod::Manual);
        assert_eq!(model.kind, None);
        assert_eq!(model.supports_session_termination, None);
        assert!(
            model.password_policy.is_some(),
            "a manual target still carries the rules the operator follows"
        );
    }

    /// The write-side refusal from the module docs: a kind this SDK could not name on the way in
    /// cannot be sent back out, because `__Unknown` would serialize a meaningless tinyint.
    #[test]
    fn an_unrecognized_kind_cannot_be_written_back() {
        let request = TargetSystemCreateRequest::Automatic {
            name: "Prod SQL".to_string(),
            kind: TargetSystemKind::Unknown,
            password_policy: policy(),
            supports_session_termination: true,
        };

        assert!(matches!(
            RegisterTargetSystemRequestModel::try_from(request),
            Err(RotationError::UnrecognizedVariant)
        ));
    }

    #[test]
    fn an_update_request_carries_the_name_policy_and_capability() {
        let model = UpdateTargetSystemRequestModel::from(update_request());

        assert_eq!(model.name, "Prod SQL");
        assert_eq!(model.supports_session_termination, Some(true));
        assert_eq!(
            model.password_policy.expect("a policy is sent").min_length,
            14
        );
    }

    /// The create request crosses the WASM boundary as plain data, and the documented wire shape is
    /// a `method` discriminant matching the server's. A renamed variant would silently produce a
    /// body the server rejects.
    #[test]
    fn a_create_request_serializes_with_the_servers_method_discriminant() {
        let automatic = serde_json::to_value(automatic_create_request()).expect("it serializes");
        assert_eq!(automatic["method"], "automatic");
        assert_eq!(automatic["kind"], "mssql");
        assert_eq!(automatic["supportsSessionTermination"], true);
        assert_eq!(automatic["passwordPolicy"]["minLength"], 14);

        let manual = serde_json::to_value(manual_create_request()).expect("it serializes");
        assert_eq!(manual["method"], "manual");
        assert_eq!(manual["name"], "Legacy mainframe");
        assert!(manual.get("kind").is_none());
    }

    #[tokio::test]
    async fn list_maps_the_organizations_target_systems() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .withf(|org_id| *org_id == Uuid::from(organization_id()))
                .returning(move |_org_id| {
                    Ok(PamTargetSystemResponseModelListResponseModel {
                        data: Some(vec![sample_response()]),
                        ..Default::default()
                    })
                })
                .once();
        });

        let targets = client(api_client)
            .list(organization_id())
            .await
            .expect("the list succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, target_system_id());
    }

    #[tokio::test]
    async fn an_organization_with_no_target_systems_lists_empty() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamTargetSystemResponseModelListResponseModel::default())
                })
                .once();
        });

        let targets = client(api_client)
            .list(organization_id())
            .await
            .expect("an absent list is not an error");

        assert!(targets.is_empty());
    }

    #[tokio::test]
    async fn list_fails_if_any_target_system_is_malformed() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamTargetSystemResponseModelListResponseModel {
                        data: Some(vec![
                            sample_response(),
                            PamTargetSystemResponseModel {
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
            mock.pam_access_connector_rotation_target_systems_api
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
    async fn create_sends_the_request_and_returns_the_stored_target_system() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_post()
                .withf(|org_id, request| {
                    *org_id == Uuid::from(organization_id())
                        && request.name == "Prod SQL"
                        && request.method == ApiTargetSystemMethod::Automatic
                        && request.kind == Some(ApiTargetSystemKind::Mssql)
                        && request.supports_session_termination == Some(true)
                })
                .returning(move |_org_id, _request| Ok(sample_response()))
                .once();
        });

        let target = client(api_client)
            .create(organization_id(), automatic_create_request())
            .await
            .expect("creation succeeds");

        assert_eq!(target.id, target_system_id());
    }

    #[tokio::test]
    async fn creating_a_manual_target_sends_no_integration() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_post()
                .withf(|_org_id, request| {
                    request.method == ApiTargetSystemMethod::Manual
                        && request.kind.is_none()
                        && request.supports_session_termination.is_none()
                })
                .returning(move |_org_id, _request| {
                    Ok(PamTargetSystemResponseModel {
                        method: Some(ApiTargetSystemMethod::Manual),
                        kind: None,
                        supports_session_termination: None,
                        ..sample_response()
                    })
                })
                .once();
        });

        let target = client(api_client)
            .create(organization_id(), manual_create_request())
            .await
            .expect("creation succeeds");

        assert_eq!(target.method, TargetSystemMethod::Manual);
        assert_eq!(target.kind, None);
    }

    /// Validation runs before the request is sent, for both methods - the accessors it reads the
    /// name and policy through have to work on either variant. The mock has no expectations, so
    /// any call to the server fails the test.
    #[tokio::test]
    async fn create_rejects_an_invalid_request_before_calling_the_server() {
        let unsatisfiable = PasswordPolicy {
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
            ..policy()
        };

        let cases = [
            (
                TargetSystemCreateRequest::Automatic {
                    name: "  ".to_string(),
                    kind: TargetSystemKind::Mssql,
                    password_policy: policy(),
                    supports_session_termination: true,
                },
                RotationValidationError::InvalidName,
            ),
            (
                TargetSystemCreateRequest::Manual {
                    name: String::new(),
                    password_policy: policy(),
                },
                RotationValidationError::InvalidName,
            ),
            (
                TargetSystemCreateRequest::Automatic {
                    name: "Prod SQL".to_string(),
                    kind: TargetSystemKind::Mssql,
                    password_policy: unsatisfiable.clone(),
                    supports_session_termination: true,
                },
                RotationValidationError::NoCharacterClasses,
            ),
            (
                TargetSystemCreateRequest::Manual {
                    name: "Legacy mainframe".to_string(),
                    password_policy: PasswordPolicy {
                        min_length: 64,
                        max_length: 14,
                        ..policy()
                    },
                },
                RotationValidationError::InvalidPasswordLengthBounds,
            ),
        ];

        for (request, expected) in cases {
            let result = client(ApiClient::new_mocked(|_| {}))
                .create(organization_id(), request)
                .await;

            assert!(
                matches!(result, Err(RotationError::Validation(ref actual)) if *actual == expected),
                "expected {expected:?}, got {result:?}"
            );
        }
    }

    /// A kind the SDK cannot name is refused while building the body, which is still before the
    /// call - so no half-described target system is created.
    #[tokio::test]
    async fn create_refuses_an_unrecognized_kind_before_calling_the_server() {
        let result = client(ApiClient::new_mocked(|_| {}))
            .create(
                organization_id(),
                TargetSystemCreateRequest::Automatic {
                    name: "Prod SQL".to_string(),
                    kind: TargetSystemKind::Unknown,
                    password_policy: policy(),
                    supports_session_termination: true,
                },
            )
            .await;

        assert!(matches!(result, Err(RotationError::UnrecognizedVariant)));
    }

    #[tokio::test]
    async fn update_sends_the_request_to_the_requested_target_system() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_put()
                .withf(|org_id, id, request| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(target_system_id())
                        && request.name == "Prod SQL"
                        && request.supports_session_termination == Some(true)
                })
                .returning(move |_org_id, _id, _request| Ok(()))
                .once();
        });

        client(api_client)
            .update(organization_id(), target_system_id(), update_request())
            .await
            .expect("the update succeeds");
    }

    #[tokio::test]
    async fn update_rejects_an_invalid_request_before_calling_the_server() {
        for (request, expected) in [
            (
                TargetSystemUpdateRequest {
                    name: "   ".to_string(),
                    ..update_request()
                },
                RotationValidationError::InvalidName,
            ),
            (
                TargetSystemUpdateRequest {
                    password_policy: PasswordPolicy {
                        max_length: 1000,
                        ..policy()
                    },
                    ..update_request()
                },
                RotationValidationError::InvalidPasswordLengthBounds,
            ),
        ] {
            let result = client(ApiClient::new_mocked(|_| {}))
                .update(organization_id(), target_system_id(), request)
                .await;

            assert!(
                matches!(result, Err(RotationError::Validation(ref actual)) if *actual == expected),
                "expected {expected:?}, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn enable_targets_the_requested_target_system() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_enable()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(target_system_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .enable(organization_id(), target_system_id())
            .await
            .expect("enabling succeeds");
    }

    #[tokio::test]
    async fn disable_targets_the_requested_target_system() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_disable()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(target_system_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .disable(organization_id(), target_system_id())
            .await
            .expect("disabling succeeds");
    }

    #[tokio::test]
    async fn disable_surfaces_an_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_disable()
                .returning(move |_org_id, _id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::CONFLICT,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client)
            .disable(organization_id(), target_system_id())
            .await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }

    #[tokio::test]
    async fn delete_targets_the_requested_target_system() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_delete()
                .withf(|org_id, id| {
                    *org_id == Uuid::from(organization_id())
                        && *id == Uuid::from(target_system_id())
                })
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        client(api_client)
            .delete(organization_id(), target_system_id())
            .await
            .expect("deleting succeeds");
    }

    /// The server, not the SDK, holds the "no config may still name it" precondition. That refusal
    /// has to reach the caller as an error - reading it as success would take a target off the
    /// operator's list while the server still has it.
    #[tokio::test]
    async fn delete_surfaces_the_refusal_when_a_config_still_names_the_target() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_delete()
                .returning(move |_org_id, _id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::CONFLICT,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client)
            .delete(organization_id(), target_system_id())
            .await;

        assert!(matches!(result, Err(RotationError::Api(_))));
    }
}
