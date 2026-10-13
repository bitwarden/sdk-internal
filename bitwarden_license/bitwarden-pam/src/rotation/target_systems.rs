use std::sync::Arc;

use bitwarden_api_api::models::{
    PamTargetSystemMethod as ApiTargetSystemMethod, PamTargetSystemResponseModel,
    RegisterTargetSystemRequestModel, UpdateTargetSystemRequestModel,
};
use bitwarden_core::{
    FromClient, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{CryptoError, Decryptable, IdentifyKey, KeyStore, KeyStoreContext};
use bitwarden_error::bitwarden_error;
use bitwarden_pam_sealed::{SealedTargetSystemKind, SealedTargetSystemMethod, seal_target_system};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    error::RotationError,
    models::{PasswordPolicy, TargetSystemKind, TargetSystemMethod, TargetSystemStatus},
    seal::{target_system_sealed_data, unseal_target},
    validate::{RotationValidationError, validate_target_system_request},
};
use crate::TargetSystemId;

/// A target system as the server returns it, with its security-relevant fields still sealed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TargetSystem {
    id: TargetSystemId,
    organization_id: OrganizationId,
    name: String,
    method: TargetSystemMethod,
    status: TargetSystemStatus,
    sealed_data: Option<String>,
    creation_date: DateTime<Utc>,
    revision_date: DateTime<Utc>,
}

impl TargetSystem {
    /// `organization_id` must be the queried id, not `response.organization_id`; see `seal`.
    pub(super) fn from_response(
        organization_id: OrganizationId,
        response: PamTargetSystemResponseModel,
    ) -> Result<Self, RotationError> {
        let sealed_data = if response.organization_id == Some(organization_id.into()) {
            response.sealed_data
        } else {
            tracing::debug!("PAM target system organization_id mismatch");
            None
        };

        Ok(Self {
            id: TargetSystemId::new(require!(response.id)),
            organization_id,
            name: require!(response.name),
            method: require!(response.method).into(),
            status: require!(response.status).into(),
            sealed_data,
            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}

impl IdentifyKey<SymmetricKeySlotId> for TargetSystem {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::Organization(self.organization_id)
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, TargetSystemView> for TargetSystem {
    /// Never fails: a blob that can't be verified leaves [`TargetSystemView::sealed`] `None`.
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<TargetSystemView, CryptoError> {
        Ok(TargetSystemView {
            id: self.id,
            organization_id: self.organization_id,
            name: self.name.clone(),
            method: self.method,
            status: self.status,
            sealed: unseal_target(
                self.sealed_data.as_deref(),
                self.status,
                self.id,
                self.method,
                key,
                ctx,
            ),
            creation_date: self.creation_date,
            revision_date: self.revision_date,
        })
    }
}

/// A target system a credential can be rotated against, with its sealed fields unsealed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct TargetSystemView {
    /// The target system's unique identifier.
    pub id: TargetSystemId,
    /// The organization this target system belongs to.
    pub organization_id: OrganizationId,
    /// Display name. Plaintext organization configuration, not vault data.
    pub name: String,
    /// How credentials are rotated for this target.
    pub method: TargetSystemMethod,
    /// Lifecycle state.
    pub status: TargetSystemStatus,
    /// `None` if the blob is not sealed yet, fails to unseal, or disagrees with this row's ID or
    /// method.
    pub sealed: Option<TargetSystemSealedFields>,
    /// The target system's creation time (UTC).
    pub creation_date: DateTime<Utc>,
    /// The target system's last-modified time (UTC).
    pub revision_date: DateTime<Utc>,
}

/// Security-relevant fields of a target system; the server only stores them sealed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct TargetSystemSealedFields {
    /// The integration behind the target. `None` only for a
    /// [`Manual`](TargetSystemMethod::Manual) target.
    pub kind: Option<TargetSystemKind>,
    /// Constraints the rotated credential must satisfy.
    pub password_policy: PasswordPolicy,
    /// Whether the integration can terminate sessions after rotating. `None` for
    /// [`Manual`](TargetSystemMethod::Manual) targets.
    pub supports_session_termination: Option<bool>,
}

/// Request to create or update a target system. Method and kind can't change after creation, but
/// [`TargetSystemsClient::update`] still takes the full shape.
///
/// Serializes with a `method` discriminant matching the server's own.
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
        /// The rules the operator is expected to follow by hand; nothing enforces them, since
        /// no connector runs a manual rotation.
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

impl From<&TargetSystemCreateRequest> for RegisterTargetSystemRequestModel {
    fn from(request: &TargetSystemCreateRequest) -> Self {
        Self {
            name: request.name().to_string(),
            method: match request {
                TargetSystemCreateRequest::Automatic { .. } => ApiTargetSystemMethod::Automatic,
                TargetSystemCreateRequest::Manual { .. } => ApiTargetSystemMethod::Manual,
            },
        }
    }
}

/// Failure from [`TargetSystemsClient::create`].
///
/// `full` mode (unlike [`RotationError`]) so [`Self::id`] crosses the FFI boundary: sealing can
/// fail after the `POST` assigned an ID, leaving a row to retry or delete.
#[bitwarden_error(full)]
#[derive(Debug, Error)]
#[error("{message}")]
pub struct TargetSystemCreateError {
    /// `None` means nothing was created.
    pub id: Option<TargetSystemId>,
    /// Never contains sealed field values.
    pub message: String,
}

/// Client for PAM rotation target-system operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct TargetSystemsClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl TargetSystemsClient {
    /// Lists the organization's target systems.
    pub async fn list(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<TargetSystemView>, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .get_all(organization_id.into())
            .await?;

        let targets = response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|item| TargetSystem::from_response(organization_id, item))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.key_store.decrypt_list(&targets)?)
    }

    /// Registers a target system with a `POST`, leaving it
    /// [`PendingSeal`](TargetSystemStatus::PendingSeal), then seals its blob under the new ID and
    /// `PUT`s it. If the second phase fails the row stays `PendingSeal`; retry via
    /// [`Self::update`] with the same request, or [`Self::delete`] it.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        request: TargetSystemCreateRequest,
    ) -> Result<TargetSystemView, TargetSystemCreateError> {
        let (id, phase_one) = self
            .register(organization_id, &request)
            .await
            .map_err(|error| TargetSystemCreateError {
                id: None,
                message: error.to_string(),
            })?;

        self.seal_and_finish(organization_id, id, &phase_one, &request)
            .await
            .map_err(|error| TargetSystemCreateError {
                id: Some(id),
                message: error.to_string(),
            })
    }

    /// Phase 1 of [`Self::create`].
    async fn register(
        &self,
        organization_id: OrganizationId,
        request: &TargetSystemCreateRequest,
    ) -> Result<(TargetSystemId, PamTargetSystemResponseModel), RotationError> {
        validate_target_system_request(request)?;
        // Reject an unsealable kind now, rather than leave a `PendingSeal` row behind.
        if let TargetSystemCreateRequest::Automatic { kind, .. } = request {
            SealedTargetSystemKind::try_from(*kind)?;
        }

        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .post(organization_id.into(), request.into())
            .await?;

        let id = TargetSystemId::new(require!(response.id));
        Ok((id, response))
    }

    /// Phase 2 of [`Self::create`]. The `PUT` returns no content, so `revision_date` is the
    /// phase-1 value.
    async fn seal_and_finish(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
        phase_one: &PamTargetSystemResponseModel,
        request: &TargetSystemCreateRequest,
    ) -> Result<TargetSystemView, RotationError> {
        self.put_sealed(organization_id, id, request).await?;

        let creation_date: DateTime<Utc> = require!(phase_one.creation_date.clone()).parse()?;

        Ok(TargetSystemView {
            id,
            organization_id,
            name: request.name().to_string(),
            method: match request {
                TargetSystemCreateRequest::Automatic { .. } => TargetSystemMethod::Automatic,
                TargetSystemCreateRequest::Manual { .. } => TargetSystemMethod::Manual,
            },
            status: TargetSystemStatus::Active,
            sealed: Some(TargetSystemSealedFields {
                kind: match request {
                    TargetSystemCreateRequest::Automatic { kind, .. } => Some(*kind),
                    TargetSystemCreateRequest::Manual { .. } => None,
                },
                password_policy: request.password_policy().clone(),
                supports_session_termination: match request {
                    TargetSystemCreateRequest::Automatic {
                        supports_session_termination,
                        ..
                    } => Some(*supports_session_termination),
                    TargetSystemCreateRequest::Manual { .. } => None,
                },
            }),
            creation_date,
            revision_date: creation_date,
        })
    }

    /// Re-seals the whole blob, so every field must be resupplied. Also how a
    /// [`PendingSeal`](TargetSystemStatus::PendingSeal) row left by a failed [`Self::create`]
    /// becomes [`Active`](TargetSystemStatus::Active).
    ///
    /// Rejects a `method` change, and a `kind` change when the existing blob is verified.
    pub async fn update(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
        request: TargetSystemCreateRequest,
    ) -> Result<(), RotationError> {
        validate_target_system_request(&request)?;
        if let TargetSystemCreateRequest::Automatic { kind, .. } = &request {
            SealedTargetSystemKind::try_from(*kind)?;
        }

        let existing = self.existing(organization_id, id).await?;

        let request_method = match &request {
            TargetSystemCreateRequest::Automatic { .. } => TargetSystemMethod::Automatic,
            TargetSystemCreateRequest::Manual { .. } => TargetSystemMethod::Manual,
        };
        if request_method != existing.method {
            return Err(RotationValidationError::TargetSystemMethodMismatch.into());
        }

        if let Some(existing_sealed) = &existing.sealed {
            let request_kind = match &request {
                TargetSystemCreateRequest::Automatic { kind, .. } => Some(*kind),
                TargetSystemCreateRequest::Manual { .. } => None,
            };
            if request_kind != existing_sealed.kind {
                return Err(RotationValidationError::TargetSystemKindMismatch.into());
            }
        }

        self.put_sealed(organization_id, id, &request).await
    }

    /// There is no single-target `GET`, so this lists and converts only `id`'s row.
    async fn existing(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
    ) -> Result<TargetSystemView, RotationError> {
        let response = self
            .api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .get_all(organization_id.into())
            .await?;

        let item = response
            .data
            .unwrap_or_default()
            .into_iter()
            .find(|item| item.id == Some(id.into()))
            .ok_or(RotationError::TargetSystemNotFound)?;

        let target = TargetSystem::from_response(organization_id, item)?;
        Ok(self.key_store.decrypt(&target)?)
    }

    /// Seals `request` under `id` and `PUT`s it.
    async fn put_sealed(
        &self,
        organization_id: OrganizationId,
        id: TargetSystemId,
        request: &TargetSystemCreateRequest,
    ) -> Result<(), RotationError> {
        let sealed_data = {
            let organization_key = SymmetricKeySlotId::Organization(organization_id);
            let mut ctx = self.key_store.context_mut();
            if !ctx.has_symmetric_key(organization_key) {
                return Err(RotationError::MissingOrganizationKey);
            }

            let method = match request {
                TargetSystemCreateRequest::Automatic { .. } => SealedTargetSystemMethod::Automatic,
                TargetSystemCreateRequest::Manual { .. } => SealedTargetSystemMethod::Manual,
            };
            let kind = match request {
                TargetSystemCreateRequest::Automatic { kind, .. } => {
                    Some(SealedTargetSystemKind::try_from(*kind)?)
                }
                TargetSystemCreateRequest::Manual { .. } => None,
            };
            let supports_session_termination = match request {
                TargetSystemCreateRequest::Automatic {
                    supports_session_termination,
                    ..
                } => Some(*supports_session_termination),
                TargetSystemCreateRequest::Manual { .. } => None,
            };
            let password_policy = request.password_policy().clone().into();

            let data = target_system_sealed_data(
                id,
                method,
                kind,
                password_policy,
                supports_session_termination,
            );
            seal_target_system::<KeySlotIds>(data, &organization_key, &mut ctx)?
        };

        self.api_configurations
            .api_client
            .pam_access_connector_rotation_target_systems_api()
            .put(
                organization_id.into(),
                id.into(),
                UpdateTargetSystemRequestModel {
                    name: request.name().to_string(),
                    sealed_data,
                },
            )
            .await?;

        Ok(())
    }

    /// Puts a disabled target system back into service; new rotation jobs dispatch for it again.
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

    /// Permanently deletes a target system. The server refuses while any rotation config still
    /// names the target; delete those configs first, or [`disable`](TargetSystemsClient::disable)
    /// a target that is only unavailable.
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
            PamTargetSystemResponseModelListResponseModel,
            PamTargetSystemStatus as ApiTargetSystemStatus,
        },
    };
    use bitwarden_core::key_management::create_test_crypto_with_user_and_org_key;
    use bitwarden_crypto::{KeyStoreContext, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_pam_sealed::{SealedPasswordPolicy, TargetSystemSealedV1, unseal_target_system};
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::rotation::validate::RotationValidationError;

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn target_system_id() -> TargetSystemId {
        TargetSystemId::new(uuid!("22222222-2222-2222-2222-222222222222"))
    }

    fn organization_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac)
    }

    fn client(api_client: ApiClient) -> TargetSystemsClient {
        client_with_org_key(api_client, organization_key())
    }

    fn client_with_org_key(
        api_client: ApiClient,
        organization_key: SymmetricCryptoKey,
    ) -> TargetSystemsClient {
        TargetSystemsClient {
            key_store: create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key,
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 14,
            max_length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: false,
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

    /// `organization_key` is the key `client()` installs for `organization_id()`.
    fn seal_with(organization_key: &SymmetricCryptoKey, data: TargetSystemSealedV1) -> String {
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();
        bitwarden_pam_sealed::seal_target_system::<KeySlotIds>(
            data,
            &SymmetricKeySlotId::Organization(organization_id()),
            &mut ctx,
        )
        .expect("sealing succeeds")
    }

    fn sealed_policy() -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length: 14,
            max_length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: false,
        }
    }

    fn sample_sealed_data() -> TargetSystemSealedV1 {
        TargetSystemSealedV1 {
            target_system_id: target_system_id().into(),
            method: SealedTargetSystemMethod::Automatic,
            kind: Some(bitwarden_pam_sealed::SealedTargetSystemKind::Mssql),
            password_policy: sealed_policy(),
            supports_session_termination: Some(true),
        }
    }

    fn target_view(
        organization_id: OrganizationId,
        response: PamTargetSystemResponseModel,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<TargetSystemView, RotationError> {
        let target = TargetSystem::from_response(organization_id, response)?;
        let key = target.key_identifier();
        Ok(target.decrypt(ctx, key)?)
    }

    /// An automatic, sealed, active target with every field populated, so a test that clears one
    /// is unambiguous about which field it is exercising.
    fn sample_response(organization_key: &SymmetricCryptoKey) -> PamTargetSystemResponseModel {
        PamTargetSystemResponseModel {
            id: Some(target_system_id().into()),
            organization_id: Some(organization_id().into()),
            name: Some("Prod SQL".to_string()),
            method: Some(ApiTargetSystemMethod::Automatic),
            status: Some(ApiTargetSystemStatus::Active),
            sealed_data: Some(seal_with(organization_key, sample_sealed_data())),
            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
            revision_date: Some("2026-01-15T00:00:00Z".to_string()),
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

        let target = target_view(
            organization_id(),
            sample_response(&organization_key),
            &mut ctx,
        )
        .expect("the payload is valid");

        assert_eq!(target.id, target_system_id());
        assert_eq!(target.organization_id, organization_id());
        assert_eq!(target.name, "Prod SQL");
        assert_eq!(target.method, TargetSystemMethod::Automatic);
        assert_eq!(target.status, TargetSystemStatus::Active);
        let sealed = target.sealed.expect("the blob is sealed");
        assert_eq!(sealed.kind, Some(TargetSystemKind::Mssql));
        assert_eq!(sealed.password_policy, policy());
        assert_eq!(sealed.supports_session_termination, Some(true));
        assert_eq!(
            target.creation_date,
            "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            target.revision_date,
            "2026-01-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn a_pending_seal_target_has_no_sealed_fields() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let response = PamTargetSystemResponseModel {
            status: Some(ApiTargetSystemStatus::PendingSeal),
            sealed_data: None,
            ..sample_response(&organization_key)
        };

        let target =
            target_view(organization_id(), response, &mut ctx).expect("the payload is valid");

        assert_eq!(target.status, TargetSystemStatus::PendingSeal);
        assert_eq!(target.sealed, None);
    }

    /// Garbage bytes, a blob sealed for another target, and a sealed `method` mismatch.
    #[test]
    fn invalid_blobs_degrade_to_no_sealed_fields() {
        let organization_key = organization_key();
        let other_target_blob = seal_with(
            &organization_key,
            TargetSystemSealedV1 {
                target_system_id: uuid!("99999999-9999-9999-9999-999999999999"),
                ..sample_sealed_data()
            },
        );
        let wrong_method_blob = seal_with(
            &organization_key,
            TargetSystemSealedV1 {
                method: SealedTargetSystemMethod::Manual,
                ..sample_sealed_data()
            },
        );

        for sealed_data in [
            Some("not a sealed blob".to_string()),
            Some(other_target_blob),
            Some(wrong_method_blob),
            None,
        ] {
            let store = create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key.clone(),
            );
            let mut ctx: KeyStoreContext<'_, KeySlotIds> = store.context_mut();

            let response = PamTargetSystemResponseModel {
                sealed_data,
                ..sample_response(&organization_key)
            };

            let target =
                target_view(organization_id(), response, &mut ctx).expect("the payload is valid");

            assert_eq!(target.sealed, None, "for status {:?}", target.status);
        }
    }

    /// A hostile server serves org B's item, with org B's validly-sealed blob, in org A's list.
    #[test]
    fn a_blob_from_a_different_organization_is_not_trusted() {
        let org_a = organization_id();
        let org_b = OrganizationId::new(uuid!("55555555-5555-5555-5555-555555555555"));
        let org_a_key = organization_key();
        let org_b_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // The caller holds both orgs' keys.
        let org_b_blob = seal_with(&org_b_key, sample_sealed_data());

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

        let response = PamTargetSystemResponseModel {
            organization_id: Some(org_b.into()),
            sealed_data: Some(org_b_blob),
            ..sample_response(&organization_key())
        };

        let mut ctx = store.context_mut();
        let target = target_view(org_a, response, &mut ctx)
            .expect("the payload is still structurally valid");

        assert_eq!(target.organization_id, org_a);
        assert_eq!(target.sealed, None);
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
            PamTargetSystemResponseModel {
                id: None,
                ..sample_response(&organization_key)
            },
            // `organization_id: None` degrades instead; see
            // `a_blob_from_a_different_organization_is_not_trusted`.
            PamTargetSystemResponseModel {
                name: None,
                ..sample_response(&organization_key)
            },
            PamTargetSystemResponseModel {
                method: None,
                ..sample_response(&organization_key)
            },
            PamTargetSystemResponseModel {
                status: None,
                ..sample_response(&organization_key)
            },
            PamTargetSystemResponseModel {
                creation_date: None,
                ..sample_response(&organization_key)
            },
            PamTargetSystemResponseModel {
                revision_date: None,
                ..sample_response(&organization_key)
            },
        ] {
            assert!(matches!(
                target_view(organization_id(), response, &mut ctx),
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
            PamTargetSystemResponseModel {
                creation_date: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
            PamTargetSystemResponseModel {
                revision_date: Some("not a date".to_string()),
                ..sample_response(&organization_key)
            },
        ] {
            assert!(matches!(
                target_view(organization_id(), response, &mut ctx),
                Err(RotationError::Chrono(_))
            ));
        }
    }

    #[test]
    fn unrecognized_enum_values_degrade_to_unknown() {
        let organization_key = organization_key();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            organization_id(),
            organization_key.clone(),
        );
        let mut ctx = store.context_mut();

        let response = PamTargetSystemResponseModel {
            method: Some(ApiTargetSystemMethod::__Unknown(9)),
            status: Some(ApiTargetSystemStatus::__Unknown(9)),
            ..sample_response(&organization_key)
        };

        let target =
            target_view(organization_id(), response, &mut ctx).expect("unknown values still map");

        assert_eq!(target.method, TargetSystemMethod::Unknown);
        assert_eq!(target.status, TargetSystemStatus::Unknown);
        // An unrecognized method never matches the sealed method, so this degrades too.
        assert_eq!(target.sealed, None);
    }

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
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .withf(|org_id| *org_id == Uuid::from(organization_id()))
                    .returning(move |_org_id| {
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            data: Some(vec![sample_response(&organization_key)]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let targets = client_with_org_key(api_client, organization_key)
            .list(organization_id())
            .await
            .expect("the list succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, target_system_id());
        assert!(targets[0].sealed.is_some());
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
    async fn list_returns_the_rest_when_one_item_has_an_invalid_blob() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        let bad = PamTargetSystemResponseModel {
                            id: Some(uuid!("33333333-3333-3333-3333-333333333333")),
                            sealed_data: Some("not a sealed blob".to_string()),
                            ..sample_response(&organization_key)
                        };
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            data: Some(vec![sample_response(&organization_key), bad]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let targets = client_with_org_key(api_client, organization_key)
            .list(organization_id())
            .await
            .expect("one invalid item does not fail the list");

        assert_eq!(targets.len(), 2);
        assert!(targets[0].sealed.is_some());
        assert_eq!(targets[1].sealed, None);
    }

    #[tokio::test]
    async fn list_fails_if_a_required_field_is_missing() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            data: Some(vec![
                                sample_response(&organization_key),
                                PamTargetSystemResponseModel {
                                    id: None,
                                    ..sample_response(&organization_key)
                                },
                            ]),
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
    async fn create_seals_the_put_body_with_the_phase_one_id() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_post()
                    .withf(|org_id, request| {
                        *org_id == Uuid::from(organization_id())
                            && request.name == "Prod SQL"
                            && request.method == ApiTargetSystemMethod::Automatic
                    })
                    .returning(move |_org_id, _request| {
                        Ok(PamTargetSystemResponseModel {
                            id: Some(target_system_id().into()),
                            organization_id: Some(organization_id().into()),
                            name: Some("Prod SQL".to_string()),
                            method: Some(ApiTargetSystemMethod::Automatic),
                            status: Some(ApiTargetSystemStatus::PendingSeal),
                            sealed_data: None,
                            creation_date: Some("2026-01-01T00:00:00Z".to_string()),
                            revision_date: Some("2026-01-01T00:00:00Z".to_string()),
                            ..Default::default()
                        })
                    })
                    .once();

                let organization_key = organization_key.clone();
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_put()
                    .withf(move |org_id, id, request| {
                        if *org_id != Uuid::from(organization_id())
                            || *id != Uuid::from(target_system_id())
                            || request.name != "Prod SQL"
                        {
                            return false;
                        }

                        let store = create_test_crypto_with_user_and_org_key(
                            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                            organization_id(),
                            organization_key.clone(),
                        );
                        let mut ctx = store.context_mut();
                        let unsealed = unseal_target_system::<KeySlotIds>(
                            &request.sealed_data,
                            &SymmetricKeySlotId::Organization(organization_id()),
                            &mut ctx,
                        )
                        .expect("the blob unseals under the organization key");

                        unsealed.target_system_id == Uuid::from(target_system_id())
                            && unsealed.method == SealedTargetSystemMethod::Automatic
                            && unsealed.kind
                                == Some(bitwarden_pam_sealed::SealedTargetSystemKind::Mssql)
                            && unsealed.supports_session_termination == Some(true)
                            && unsealed.password_policy == sealed_policy()
                    })
                    .returning(move |_org_id, _id, _request| Ok(()))
                    .once();
            })
        };

        let target = client_with_org_key(api_client, organization_key)
            .create(organization_id(), automatic_create_request())
            .await
            .expect("creation succeeds");

        assert_eq!(target.id, target_system_id());
        assert_eq!(target.status, TargetSystemStatus::Active);
        assert_eq!(
            target.sealed.and_then(|sealed| sealed.kind),
            Some(TargetSystemKind::Mssql)
        );
    }

    #[tokio::test]
    async fn create_reports_the_id_when_phase_two_fails() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_post()
                .returning(move |_org_id, _request| {
                    Ok(PamTargetSystemResponseModel {
                        id: Some(target_system_id().into()),
                        organization_id: Some(organization_id().into()),
                        name: Some("Prod SQL".to_string()),
                        method: Some(ApiTargetSystemMethod::Automatic),
                        status: Some(ApiTargetSystemStatus::PendingSeal),
                        sealed_data: None,
                        creation_date: Some("2026-01-01T00:00:00Z".to_string()),
                        revision_date: Some("2026-01-01T00:00:00Z".to_string()),
                        ..Default::default()
                    })
                })
                .once();

            mock.pam_access_connector_rotation_target_systems_api
                .expect_put()
                .returning(move |_org_id, _id, _request| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client)
            .create(organization_id(), automatic_create_request())
            .await;

        let error = result.expect_err("phase 2 failed");
        assert_eq!(error.id, Some(target_system_id()));
    }

    /// Nothing is created when local validation fails, so the error carries no ID.
    #[tokio::test]
    async fn create_rejects_an_invalid_request_before_calling_the_server() {
        let unsatisfiable = PasswordPolicy {
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
            ..policy()
        };

        for request in [
            TargetSystemCreateRequest::Automatic {
                name: "  ".to_string(),
                kind: TargetSystemKind::Mssql,
                password_policy: policy(),
                supports_session_termination: true,
            },
            TargetSystemCreateRequest::Manual {
                name: String::new(),
                password_policy: policy(),
            },
            TargetSystemCreateRequest::Automatic {
                name: "Prod SQL".to_string(),
                kind: TargetSystemKind::Mssql,
                password_policy: unsatisfiable.clone(),
                supports_session_termination: true,
            },
        ] {
            let result = client(ApiClient::new_mocked(|_| {}))
                .create(organization_id(), request)
                .await;

            let error = result.expect_err("the request is invalid");
            assert_eq!(error.id, None);
        }
    }

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

        let error = result.expect_err("an unrecognized kind is refused");
        assert_eq!(error.id, None);
    }

    #[tokio::test]
    async fn update_seals_and_sends_the_request_to_the_requested_target_system() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                let existing_key = organization_key.clone();
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            data: Some(vec![sample_response(&existing_key)]),
                            ..Default::default()
                        })
                    })
                    .once();

                mock.pam_access_connector_rotation_target_systems_api
                    .expect_put()
                    .withf(move |org_id, id, request| {
                        if *org_id != Uuid::from(organization_id())
                            || *id != Uuid::from(target_system_id())
                            || request.name != "Prod SQL"
                        {
                            return false;
                        }

                        let store = create_test_crypto_with_user_and_org_key(
                            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                            organization_id(),
                            organization_key.clone(),
                        );
                        let mut ctx = store.context_mut();
                        let unsealed = unseal_target_system::<KeySlotIds>(
                            &request.sealed_data,
                            &SymmetricKeySlotId::Organization(organization_id()),
                            &mut ctx,
                        )
                        .expect("the blob unseals under the organization key");

                        unsealed.target_system_id == Uuid::from(target_system_id())
                    })
                    .returning(move |_org_id, _id, _request| Ok(()))
                    .once();
            })
        };

        client_with_org_key(api_client, organization_key)
            .update(
                organization_id(),
                target_system_id(),
                automatic_create_request(),
            )
            .await
            .expect("the update succeeds");
    }

    #[tokio::test]
    async fn update_rejects_an_invalid_request_before_calling_the_server() {
        let result = client(ApiClient::new_mocked(|_| {}))
            .update(
                organization_id(),
                target_system_id(),
                TargetSystemCreateRequest::Automatic {
                    name: "   ".to_string(),
                    kind: TargetSystemKind::Mssql,
                    password_policy: policy(),
                    supports_session_termination: true,
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::InvalidName
            ))
        ));
    }

    /// Refused before sealing or sending anything.
    #[tokio::test]
    async fn update_rejects_a_method_different_from_the_existing_target() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            // Existing target is Automatic.
                            data: Some(vec![sample_response(&organization_key)]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .update(
                organization_id(),
                target_system_id(),
                // Request is Manual, disagreeing with the existing Automatic target.
                manual_create_request(),
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::TargetSystemMethodMismatch
            ))
        ));
    }

    /// Refused before sealing or sending anything.
    #[tokio::test]
    async fn update_rejects_a_kind_different_from_the_existing_sealed_target() {
        let organization_key = organization_key();
        let api_client = {
            let organization_key = organization_key.clone();
            ApiClient::new_mocked(move |mock| {
                mock.pam_access_connector_rotation_target_systems_api
                    .expect_get_all()
                    .returning(move |_org_id| {
                        Ok(PamTargetSystemResponseModelListResponseModel {
                            // Existing target has sealed kind Mssql (see `sample_sealed_data`).
                            data: Some(vec![sample_response(&organization_key)]),
                            ..Default::default()
                        })
                    })
                    .once();
            })
        };

        let result = client_with_org_key(api_client, organization_key)
            .update(
                organization_id(),
                target_system_id(),
                TargetSystemCreateRequest::Automatic {
                    name: "Prod SQL".to_string(),
                    // Request names Entra, disagreeing with the sealed Mssql.
                    kind: TargetSystemKind::Entra,
                    password_policy: policy(),
                    supports_session_termination: true,
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(RotationError::Validation(
                RotationValidationError::TargetSystemKindMismatch
            ))
        ));
    }

    #[tokio::test]
    async fn update_fails_when_the_target_system_does_not_exist() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.pam_access_connector_rotation_target_systems_api
                .expect_get_all()
                .returning(move |_org_id| {
                    Ok(PamTargetSystemResponseModelListResponseModel::default())
                })
                .once();
        });

        let result = client(api_client)
            .update(
                organization_id(),
                target_system_id(),
                automatic_create_request(),
            )
            .await;

        assert!(matches!(result, Err(RotationError::TargetSystemNotFound)));
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

    /// The server holds the "no config may still name it" precondition, and its refusal must reach
    /// the caller as an error rather than read as a deleted target.
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
