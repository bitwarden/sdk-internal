//! Updates the account recovery keys of members who have upgraded to a V2 user key.
//!
//! A member upgrading to V2 leaves their organizations holding an account recovery key that still
//! wraps their V1 user key. Only an owner or admin can replace it, so the migration runs for every
//! organization the account administers.

use bitwarden_core::{Client, FromClient, OrganizationId};
use bitwarden_member_administration::OrganizationUsersManagementClient;
use bitwarden_organizations::{OrganizationsClient, ProfileOrganization};
use tracing::warn;

pub(crate) struct AccountRecoveryV2UpgradeMigration {
    organizations: OrganizationsClient,
    organization_users_management: OrganizationUsersManagementClient,
}

impl FromClient for AccountRecoveryV2UpgradeMigration {
    fn from_client(client: &Client) -> Self {
        Self {
            organizations: OrganizationsClient::from_client(client),
            organization_users_management: OrganizationUsersManagementClient::from_client(client),
        }
    }
}

impl AccountRecoveryV2UpgradeMigration {
    pub(crate) async fn run(&self) {
        let organizations = match self.organizations.get_all().await {
            Ok(organizations) => organizations,
            Err(e) => {
                warn!("Failed to read the organizations: {e}");
                return;
            }
        };

        for organization_id in self.organizations_to_upgrade(&organizations) {
            if let Err(e) = self
                .organization_users_management
                .upgrade_pending_account_recovery_keys(organization_id)
                .await
            {
                warn!(
                    %organization_id,
                    "Failed to upgrade pending account recovery keys: {e}"
                );
            }
        }
    }

    /// The organizations this account can update account recovery keys for.
    fn organizations_to_upgrade(
        &self,
        organizations: &[ProfileOrganization],
    ) -> Vec<OrganizationId> {
        organizations
            .iter()
            .filter(|o| {
                self.organization_users_management
                    .can_administer_account_recovery_keys(o.details.id, &o.membership.r#type)
            })
            .map(|o| o.details.id)
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::{ApiClient, ApiClientMock},
        models::OrganizationUserPendingV2UpgradeResponseModelListResponseModel,
    };
    use bitwarden_core::{
        ClientBuilder, client::ApiConfigurations, key_management::SymmetricKeySlotId,
    };
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_organizations::{
        OrganizationDetails, OrganizationMembership, OrganizationUserType, Permissions,
    };
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;

    pub(crate) fn organization(user_type: OrganizationUserType) -> ProfileOrganization {
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
    /// `organizations` in its state.
    pub(crate) async fn client(
        organizations: &[ProfileOrganization],
        organization_ids: &[OrganizationId],
        configure: impl FnOnce(&mut ApiClientMock),
    ) -> Client {
        let client = ClientBuilder::new()
            .with_api_configurations(Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(configure),
            )))
            .build();

        let repository = Arc::new(MemoryRepository::<ProfileOrganization>::default());
        for organization in organizations {
            repository
                .set(organization.details.id, organization.clone())
                .await
                .expect("the repository is in memory");
        }
        client
            .platform()
            .state()
            .register_client_managed(repository);

        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        for organization_id in organization_ids {
            #[allow(deprecated)]
            ctx.set_symmetric_key(
                SymmetricKeySlotId::Organization(*organization_id),
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            )
            .expect("the context is mutable");
        }
        drop(ctx);

        client
    }

    /// Answers `get_pending_v2_upgrades` for `organization_id` with no pending memberships,
    /// exactly once.
    pub(crate) fn expect_no_pending(mock: &mut ApiClientMock, organization_id: OrganizationId) {
        mock.organization_users_keys_api
            .expect_get_pending_v2_upgrades()
            .withf(move |org, _token| OrganizationId::new(*org) == organization_id)
            .returning(|_org, _token| {
                Ok(
                    OrganizationUserPendingV2UpgradeResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![]),
                        continuation_token: None,
                    },
                )
            })
            .once();
    }

    async fn run(client: &Client) {
        AccountRecoveryV2UpgradeMigration::from_client(client)
            .run()
            .await;
    }

    /// The API mock fails any request for an organization it does not expect.
    #[tokio::test]
    async fn test_only_owner_and_admin_memberships_are_upgraded() {
        let owner = organization(OrganizationUserType::Owner);
        let admin = organization(OrganizationUserType::Admin);
        // The server rejects custom members, even with every account recovery permission.
        let mut custom = organization(OrganizationUserType::Custom);
        custom.membership.permissions = Permissions {
            manage_reset_password: true,
            manage_users: true,
            ..custom.membership.permissions
        };
        let member = organization(OrganizationUserType::User);
        let (owner_id, admin_id) = (owner.details.id, admin.details.id);
        let all = [owner, admin, custom, member];
        let ids: Vec<_> = all.iter().map(|o| o.details.id).collect();

        let client = client(&all, &ids, |mock| {
            expect_no_pending(mock, owner_id);
            expect_no_pending(mock, admin_id);
        })
        .await;

        run(&client).await;
    }

    #[tokio::test]
    async fn test_memberships_without_an_organization_key_are_skipped() {
        let locked = organization(OrganizationUserType::Owner);
        let unlocked = organization(OrganizationUserType::Owner);
        let unlocked_id = unlocked.details.id;

        let client = client(&[locked, unlocked], &[unlocked_id], |mock| {
            expect_no_pending(mock, unlocked_id);
        })
        .await;

        run(&client).await;
    }

    #[tokio::test]
    async fn test_a_failed_upgrade_does_not_stop_the_other_organizations() {
        let failing = organization(OrganizationUserType::Owner);
        let succeeding = organization(OrganizationUserType::Admin);
        let (failing_id, succeeding_id) = (failing.details.id, succeeding.details.id);

        let client = client(
            &[failing, succeeding],
            &[failing_id, succeeding_id],
            |mock| {
                mock.organization_users_keys_api
                    .expect_get_pending_v2_upgrades()
                    .withf(move |org, _token| OrganizationId::new(*org) == failing_id)
                    .returning(|_org, _token| {
                        Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                            "connection reset",
                        )))
                    })
                    .once();
                expect_no_pending(mock, succeeding_id);
            },
        )
        .await;

        run(&client).await;
    }

    #[tokio::test]
    async fn test_no_organizations_upgrades_nothing() {
        let client = client(&[], &[], |_| {}).await;

        run(&client).await;
    }

    #[tokio::test]
    async fn test_no_organization_repository_upgrades_nothing() {
        let client = Client::new(None);

        run(&client).await;
    }
}
