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
/// Note that a target system cannot be deleted: the server exposes no delete route, because configs
/// reference targets and a rotation's history has to stay attributable. Retiring one is
/// [`disable`](TargetSystemsClient::disable).
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
}
