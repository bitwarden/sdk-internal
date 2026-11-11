//! Record organization key ids to the server for organizations where they were never captured.
//!
//! Key ids were introduced after organization keys, so organizations created before the server
//! started tracking them hold a key whose id the server does not know about. Every member derives
//! the same id from the organization key, but only Owners and Admins can record it.

use bitwarden_api_api::models::SetOrganizationKeyIdRequest;
use bitwarden_core::{OrganizationId, key_management::SymmetricKeySlotId};
use bitwarden_crypto::KeyId;
use bitwarden_error::bitwarden_error;
use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use thiserror::Error;
use tracing::{error, info};

use crate::OrganizationCryptoManagementClient;

/// Errors returned by the organization key id backfill.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum OrganizationKeyIdBackfillError {
    /// The organization repository is not registered or could not be read.
    #[error("Organization state is not available")]
    OrganizationStateNotAvailable(#[from] RepositoryError),
    /// One or more API calls failed. The other organizations were still attempted.
    #[error("API call failed during organization key id backfill")]
    Api,
}

#[bitwarden_ffi::wasm_export]
impl OrganizationCryptoManagementClient {
    /// Returns the organizations whose key id the server does not have, and that this account can
    /// record the key id for.
    pub async fn organization_key_ids_needing_backfill(
        &self,
    ) -> Result<Vec<OrganizationId>, OrganizationKeyIdBackfillError> {
        Ok(self
            .backfill_targets()
            .await?
            .into_iter()
            .map(|(organization_id, _)| organization_id)
            .collect())
    }

    /// Records the key id of each organization key that the server does not have.
    ///
    /// A failure for one organization does not stop the others. Returns
    /// [`OrganizationKeyIdBackfillError::Api`] when any organization failed. Makes no API calls
    /// when no organization needs a backfill.
    ///
    /// Requires the client to be unlocked so the organization keys are available in memory.
    pub async fn organization_key_id_backfill(&self) -> Result<(), OrganizationKeyIdBackfillError> {
        let mut failed = false;

        for (organization_id, key_id) in self.backfill_targets().await? {
            info!(%organization_id, "Recording the organization key id with the server");
            if let Err(e) = self
                .api_configurations
                .api_client
                .organization_keys_api()
                .set_organization_key_id(
                    organization_id.into(),
                    SetOrganizationKeyIdRequest {
                        organization_key_id: key_id.to_string(),
                    },
                )
                .await
            {
                // A 409 means the server holds a different key id for this organization.
                error!(%organization_id, "Failed to post the organization key id: {e:?}");
                failed = true;
            }
        }

        if failed {
            Err(OrganizationKeyIdBackfillError::Api)
        } else {
            Ok(())
        }
    }
}

impl OrganizationCryptoManagementClient {
    /// Returns the organizations that need a backfill, each with the id of its organization key in
    /// the key store.
    async fn backfill_targets(
        &self,
    ) -> Result<Vec<(OrganizationId, KeyId)>, OrganizationKeyIdBackfillError> {
        let organizations = self.repository.require()?.list().await?;

        let ctx = self.key_store.context();
        Ok(organizations
            .into_iter()
            // Only backfill if the org key id is not set on the server
            .filter(|o| o.details.key_id.is_none())
            // The server only authorizes confirmed Owners and Admins. It refuses custom users even
            // with every permission, and provider users who are not members.
            .filter(|o| {
                o.membership.is_member
                    && o.membership.status == OrganizationUserStatusType::Confirmed
                    && matches!(
                        o.membership.r#type,
                        OrganizationUserType::Owner | OrganizationUserType::Admin
                    )
            })
            // Without the organization key there is no key id to record.
            .filter_map(|o| {
                ctx.get_symmetric_key_id(SymmetricKeySlotId::Organization(o.details.id))
                    .map(|key_id| (o.details.id, key_id))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_api_api::apis::{ApiClient, ApiClientMock};
    use bitwarden_core::client::ApiConfigurations;
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_organizations::{
        OrganizationDetails, OrganizationMembership, Permissions, ProfileOrganization,
    };
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;

    fn organization(user_type: OrganizationUserType) -> ProfileOrganization {
        let default = ProfileOrganization::default();
        ProfileOrganization {
            details: OrganizationDetails {
                id: OrganizationId::new_v4(),
                ..default.details
            },
            membership: OrganizationMembership {
                r#type: user_type,
                ..default.membership
            },
            ..ProfileOrganization::default()
        }
    }

    /// A client holding an organization key for each of `organization_ids`, with
    /// `organizations` in its state and its API calls served by the configured mock.
    async fn client(
        organizations: &[ProfileOrganization],
        organization_ids: &[OrganizationId],
        configure: impl FnOnce(&mut ApiClientMock),
    ) -> OrganizationCryptoManagementClient {
        let repository = Arc::new(MemoryRepository::<ProfileOrganization>::default());
        for organization in organizations {
            repository
                .set(organization.details.id, organization.clone())
                .await
                .expect("the repository is in memory");
        }

        let key_store = KeyStore::default();
        {
            let mut ctx = key_store.context_mut();
            for organization_id in organization_ids {
                #[allow(deprecated)]
                ctx.set_symmetric_key(
                    SymmetricKeySlotId::Organization(*organization_id),
                    SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                )
                .expect("the context is mutable");
            }
        }

        OrganizationCryptoManagementClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(configure),
            )),
            repository: Some(repository),
        }
    }

    /// An API configuration that fails the test if the key id is posted.
    fn expect_no_posts(mock: &mut ApiClientMock) {
        mock.organization_keys_api
            .expect_set_organization_key_id()
            .never();
    }

    fn organization_key_id(
        client: &OrganizationCryptoManagementClient,
        organization_id: OrganizationId,
    ) -> String {
        client
            .key_store
            .context()
            .get_symmetric_key_id(SymmetricKeySlotId::Organization(organization_id))
            .expect("an organization key has a key id")
            .to_string()
    }

    async fn assert_backfill_posts_the_key_id(user_type: OrganizationUserType) {
        let organization = organization(user_type);
        let organization_id = organization.details.id;
        // The posted id is checked against the key store's below, so the mock only records it.
        let posted = Arc::new(Mutex::new(Vec::new()));
        let recorder = posted.clone();
        let client = client(&[organization], &[organization_id], |mock| {
            mock.organization_keys_api
                .expect_set_organization_key_id()
                .once()
                .returning(move |organization_id, body| {
                    recorder.lock().unwrap().push((
                        OrganizationId::new(organization_id),
                        body.organization_key_id,
                    ));
                    Ok(())
                });
        })
        .await;

        assert_eq!(
            client
                .organization_key_ids_needing_backfill()
                .await
                .unwrap(),
            vec![organization_id]
        );
        client.organization_key_id_backfill().await.unwrap();

        assert_eq!(
            *posted.lock().unwrap(),
            vec![(
                organization_id,
                organization_key_id(&client, organization_id)
            )]
        );
    }

    #[tokio::test]
    async fn test_backfill_posts_the_key_id_for_an_owner() {
        assert_backfill_posts_the_key_id(OrganizationUserType::Owner).await;
    }

    #[tokio::test]
    async fn test_backfill_posts_the_key_id_for_an_admin() {
        assert_backfill_posts_the_key_id(OrganizationUserType::Admin).await;
    }

    /// Asserts that no organization needs a backfill, and that the backfill posts nothing.
    async fn assert_nothing_to_backfill(
        organizations: &[ProfileOrganization],
        organization_ids: &[OrganizationId],
    ) {
        let client = client(organizations, organization_ids, expect_no_posts).await;

        assert!(
            client
                .organization_key_ids_needing_backfill()
                .await
                .unwrap()
                .is_empty()
        );
        client.organization_key_id_backfill().await.unwrap();
    }

    #[tokio::test]
    async fn test_no_backfill_when_the_server_already_knows_the_key_id() {
        let mut organization = organization(OrganizationUserType::Owner);
        organization.details.key_id = Some(KeyId::make());
        let organization_id = organization.details.id;

        assert_nothing_to_backfill(&[organization], &[organization_id]).await;
    }

    #[tokio::test]
    async fn test_no_backfill_for_custom_users_and_users() {
        // The server rejects custom members, even with every permission.
        let mut custom = organization(OrganizationUserType::Custom);
        custom.membership.permissions = Permissions {
            access_event_logs: true,
            access_import_export: true,
            access_reports: true,
            create_new_collections: true,
            edit_any_collection: true,
            delete_any_collection: true,
            manage_groups: true,
            manage_sso: true,
            manage_policies: true,
            manage_users: true,
            manage_reset_password: true,
            manage_scim: true,
            manage_access_rules: true,
            manage_rotation: true,
        };
        let user = organization(OrganizationUserType::User);
        let ids = [custom.details.id, user.details.id];

        assert_nothing_to_backfill(&[custom, user], &ids).await;
    }

    #[tokio::test]
    async fn test_no_backfill_for_provider_only_access() {
        let mut organization = organization(OrganizationUserType::Owner);
        organization.membership.is_member = false;
        organization.membership.is_provider_user = true;
        let organization_id = organization.details.id;

        assert_nothing_to_backfill(&[organization], &[organization_id]).await;
    }

    #[tokio::test]
    async fn test_no_backfill_for_a_revoked_owner() {
        let mut organization = organization(OrganizationUserType::Owner);
        organization.membership.status = OrganizationUserStatusType::Revoked;
        let organization_id = organization.details.id;

        assert_nothing_to_backfill(&[organization], &[organization_id]).await;
    }

    #[tokio::test]
    async fn test_no_backfill_without_an_organization_key() {
        let organization = organization(OrganizationUserType::Owner);

        assert_nothing_to_backfill(&[organization], &[]).await;
    }

    #[tokio::test]
    async fn test_a_failed_post_does_not_stop_the_other_organizations() {
        let failing = organization(OrganizationUserType::Owner);
        let succeeding = organization(OrganizationUserType::Admin);
        let (failing_id, succeeding_id) = (failing.details.id, succeeding.details.id);

        let client = client(
            &[failing, succeeding],
            &[failing_id, succeeding_id],
            |mock| {
                mock.organization_keys_api
                    .expect_set_organization_key_id()
                    .withf(move |org, _body| OrganizationId::new(*org) == failing_id)
                    .returning(|_org, _body| {
                        Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                            "connection reset",
                        )))
                    })
                    .once();
                mock.organization_keys_api
                    .expect_set_organization_key_id()
                    .withf(move |org, _body| OrganizationId::new(*org) == succeeding_id)
                    .returning(|_org, _body| Ok(()))
                    .once();
            },
        )
        .await;

        assert!(matches!(
            client.organization_key_id_backfill().await,
            Err(OrganizationKeyIdBackfillError::Api)
        ));
    }

    #[tokio::test]
    async fn test_errors_without_an_organization_repository() {
        let client = OrganizationCryptoManagementClient {
            repository: None,
            ..client(&[], &[], expect_no_posts).await
        };

        assert!(matches!(
            client.organization_key_ids_needing_backfill().await,
            Err(OrganizationKeyIdBackfillError::OrganizationStateNotAvailable(_))
        ));
        assert!(matches!(
            client.organization_key_id_backfill().await,
            Err(OrganizationKeyIdBackfillError::OrganizationStateNotAvailable(_))
        ));
    }
}
