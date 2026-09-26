//! Updating members' account recovery keys after their V1 to V2 upgrade.
//!
//! A V1 to V2 upgrade rotation does not re-encapsulate the member's account recovery key, because
//! that requires trusting a server-supplied organization public key and the upgrade shows the
//! member no prompt. The rotation writes a V2 upgrade token to the membership instead, and the
//! organization keeps an account recovery key that wraps the member's V1 user key.
//!
//! An organization admin decapsulates that V1 user key, reads the V2 user key out of the token,
//! and encapsulates it to the organization as the new account recovery key.
//!
//! Every pending membership is upgraded, also the ones whose new account recovery key cannot be
//! produced.

use bitwarden_api_api::models::{
    OrganizationUserPendingV2UpgradeResponseModel, OrganizationUserV2UpgradeRequestModel,
    OrganizationUserV2UpgradesRequestModel,
};
use bitwarden_core::{
    ApiError, MissingFieldError, OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId, V2UpgradeToken, V2UpgradeTokenError},
    require,
};
use bitwarden_crypto::{EncString, KeyId, KeyStoreContext, UnsignedSharedKey};
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{
    account_recovery::{decapsulate_member_user_key, encapsulate_member_user_key},
    organization_private_key::{OrganizationPrivateKey, OrganizationPrivateKeyError},
};
use bitwarden_organizations::{OrganizationUserType, Permissions};
use thiserror::Error;
use tracing::warn;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::OrganizationUsersManagementClient;

/// Errors returned when upgrading members' account recovery keys.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccountRecoveryV2UpgradeError {
    /// The request failed as a whole.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A membership field could not be parsed.
    #[error("The membership field {0} is malformed")]
    MalformedMembership(&'static str),
    /// The user key from the upgrade token does not match the membership's key id.
    #[error("The upgrade token carries a user key the reported key id does not name")]
    UserKeyIdMismatch,
    /// The user key from the upgrade token has no key id.
    #[error("The upgrade token carries a user key without a key id")]
    MissingUserKeyId,
    /// The V2 upgrade token could not be opened or failed validation.
    #[error(transparent)]
    UpgradeToken(#[from] V2UpgradeTokenError),
    /// The organization key is not in the key store.
    #[error("The organization key is not available")]
    OrganizationKeyMissing,
    /// The organization's private key could not decapsulate or encapsulate a user key.
    #[error(transparent)]
    Crypto(#[from] OrganizationPrivateKeyError),
}

/// Whether the account can read the organization's private key and set members' account recovery
/// keys.
///
/// Owners and admins always can. A custom member needs two permissions: ManageResetPassword for
/// the account recovery keys, and ManageUsers for the organization's private key.
fn has_account_recovery_permissions(
    user_type: &OrganizationUserType,
    permissions: &Permissions,
) -> bool {
    match user_type {
        OrganizationUserType::Owner | OrganizationUserType::Admin => true,
        OrganizationUserType::Custom => {
            permissions.manage_reset_password && permissions.manage_users
        }
        OrganizationUserType::User => false,
    }
}

impl OrganizationUsersManagementClient {
    /// Whether the account can update the account recovery keys of this organization's members.
    ///
    /// The account must be an owner or an admin, or a custom member with ManageResetPassword and
    /// ManageUsers. It must also hold the organization key, which unwraps the organization's
    /// private key.
    pub fn can_administer_account_recovery_keys(
        &self,
        organization_id: OrganizationId,
        user_type: &OrganizationUserType,
        permissions: &Permissions,
    ) -> bool {
        has_account_recovery_permissions(user_type, permissions)
            && self
                .key_store
                .context()
                .has_symmetric_key(SymmetricKeySlotId::Organization(organization_id))
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersManagementClient {
    /// Re-encapsulates the account recovery keys of members who have upgraded to a V2 user key.
    ///
    /// A membership whose new account recovery key cannot be produced is posted without one,
    /// which completes the upgrade and drops a key that no longer opens the member's vault.
    ///
    /// Callers that filter a list of organizations should check
    /// `can_administer_account_recovery_keys` first.
    pub async fn upgrade_pending_account_recovery_keys(
        &self,
        organization_id: OrganizationId,
    ) -> Result<(), AccountRecoveryV2UpgradeError> {
        let organization_key = SymmetricKeySlotId::Organization(organization_id);
        if !self.key_store.context().has_symmetric_key(organization_key) {
            return Err(AccountRecoveryV2UpgradeError::OrganizationKeyMissing);
        }

        let pending = self
            .api_configurations
            .api_client
            .organization_users_keys_api()
            .get_pending_v2_upgrades(organization_id.into())
            .await?
            .data
            .unwrap_or_default();

        if pending.is_empty() {
            return Ok(());
        }

        let wrapped_private_key = EncString::from(require!(
            self.api_configurations
                .api_client
                .organizations_api()
                .get_private_key(organization_id.into())
                .await?
                .private_key
        ));

        let upgrades = {
            let mut ctx = self.key_store.context();
            let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
                organization_key,
                &wrapped_private_key,
                &mut ctx,
            )?;

            pending
                .iter()
                .filter_map(|membership| {
                    // The key id is sent back unchanged, because the server checks it against the
                    // member's user row.
                    let (Some(organization_user_id), Some(user_key_id)) = (
                        membership.organization_user_id,
                        membership.user_key_id.clone(),
                    ) else {
                        warn!(
                            %organization_id,
                            organization_user_id = ?membership.organization_user_id,
                            "Skipping a membership without an id or a user key id"
                        );
                        return None;
                    };

                    let mut upgrade = OrganizationUserV2UpgradeRequestModel::new(
                        organization_user_id,
                        user_key_id,
                    );
                    upgrade.account_recovery_key = account_recovery_key(
                        &organization_private_key,
                        membership,
                        &upgrade.user_key_id,
                        &mut ctx,
                    )
                    .inspect_err(|e| {
                        warn!(
                            %organization_id,
                            organization_user_id = %upgrade.organization_user_id,
                            "Upgrading a membership without an account recovery key: {e}"
                        );
                    })
                    .ok();

                    Some(upgrade)
                })
                .collect::<Vec<_>>()
        };

        if upgrades.is_empty() {
            return Ok(());
        }

        self.api_configurations
            .api_client
            .organization_users_keys_api()
            .post_v2_upgrades(
                organization_id.into(),
                Some(OrganizationUserV2UpgradesRequestModel::new(upgrades)),
            )
            .await?;

        Ok(())
    }
}

/// Reads the V2 user key out of the membership's upgrade token and encapsulates it to the
/// organization as the member's new account recovery key.
fn account_recovery_key(
    organization_private_key: &OrganizationPrivateKey<KeySlotIds>,
    membership: &OrganizationUserPendingV2UpgradeResponseModel,
    reported_user_key_id: &str,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<String, AccountRecoveryV2UpgradeError> {
    let user_key_id: KeyId = reported_user_key_id
        .parse()
        .map_err(|_| AccountRecoveryV2UpgradeError::MalformedMembership("userKeyId"))?;
    let account_recovery_key: UnsignedSharedKey =
        require!(membership.account_recovery_key.as_ref())
            .parse()
            .map_err(|_| {
                AccountRecoveryV2UpgradeError::MalformedMembership("accountRecoveryKey")
            })?;
    let upgrade_token = V2UpgradeToken::try_from(require!(membership.v2_upgrade_token.as_deref()))?;

    let v1_user_key =
        decapsulate_member_user_key(organization_private_key, &account_recovery_key, ctx)?;
    // Unwrapping cross-validates both halves of the token, so a tampered token fails here.
    let v2_user_key = upgrade_token.unwrap_v2(v1_user_key, ctx)?;

    // The key id is posted back as the server reported it, so the server's check against the
    // member's user row cannot detect a token carrying a different key.
    let recovered_key_id = ctx
        .get_symmetric_key_id(v2_user_key)
        .ok_or(AccountRecoveryV2UpgradeError::MissingUserKeyId)?;
    if recovered_key_id != user_key_id {
        return Err(AccountRecoveryV2UpgradeError::UserKeyIdMismatch);
    }

    Ok(encapsulate_member_user_key(organization_private_key, v2_user_key, ctx)?.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            OrganizationPrivateKeyResponseModel,
            OrganizationUserPendingV2UpgradeResponseModelListResponseModel,
            V2UpgradeTokenResponseModel,
        },
    };
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{
        PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    };

    use super::*;

    /// A well-formed key id matching none of the keys under test.
    const UNRELATED_USER_KEY_ID: &str = "000102030405060708090a0b0c0d0e0f";

    /// An organization with its key in the key store and its wrapped private key.
    struct TestOrganization {
        client: OrganizationUsersManagementClient,
        organization_id: OrganizationId,
        wrapped_private_key: String,
    }

    impl TestOrganization {
        fn new(api_client: ApiClient) -> Self {
            let organization_id = OrganizationId::new_v4();
            let key_store = create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id,
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            );

            let wrapped_private_key = {
                let mut ctx = key_store.context();
                let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
                ctx.wrap_private_key(
                    SymmetricKeySlotId::Organization(organization_id),
                    private_key,
                )
                .unwrap()
                .to_string()
            };

            Self {
                client: OrganizationUsersManagementClient {
                    key_store,
                    api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
                },
                organization_id,
                wrapped_private_key,
            }
        }

        fn organization_private_key<'a>(
            &self,
            ctx: &mut KeyStoreContext<'a, KeySlotIds>,
        ) -> OrganizationPrivateKey<KeySlotIds> {
            OrganizationPrivateKey::unwrap_with_organization_key(
                SymmetricKeySlotId::Organization(self.organization_id),
                &self.wrapped_private_key.parse().unwrap(),
                ctx,
            )
            .unwrap()
        }

        /// Builds a membership mid-upgrade: the account recovery key holds the V1 user key and
        /// the upgrade token holds the V2 one. Also returns the expected V2 user key.
        fn pending_membership(
            &self,
        ) -> (
            OrganizationUserPendingV2UpgradeResponseModel,
            SymmetricCryptoKey,
        ) {
            let mut ctx = self.client.key_store.context();
            let organization_private_key = self.organization_private_key(&mut ctx);

            let v1_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let v2_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
            let token = V2UpgradeToken::create::<KeySlotIds>(v1_user_key, v2_user_key, &ctx)
                .expect("the token wraps each user key with the other");

            let account_recovery_key =
                encapsulate_member_user_key(&organization_private_key, v1_user_key, &ctx).unwrap();

            // After the upgrade the member's current user key is the V2 one.
            let user_key_id = ctx.get_symmetric_key_id(v2_user_key).unwrap();

            #[allow(deprecated)]
            let expected = ctx
                .dangerous_get_symmetric_key(v2_user_key)
                .unwrap()
                .clone();

            (
                OrganizationUserPendingV2UpgradeResponseModel {
                    object: None,
                    organization_user_id: Some(uuid::Uuid::new_v4()),
                    user_key_id: Some(user_key_id.to_string()),
                    account_recovery_key: Some(account_recovery_key.to_string()),
                    v2_upgrade_token: Some(Box::new(V2UpgradeTokenResponseModel {
                        wrapped_user_key1: Some(token.wrapped_user_key_1.to_string()),
                        wrapped_user_key2: Some(token.wrapped_user_key_2.to_string()),
                    })),
                },
                expected,
            )
        }

        /// Decapsulates a posted account recovery key.
        fn decapsulate(&self, account_recovery_key: &str) -> SymmetricCryptoKey {
            let mut ctx = self.client.key_store.context();
            let organization_private_key = self.organization_private_key(&mut ctx);
            let key_id = decapsulate_member_user_key(
                &organization_private_key,
                &account_recovery_key.parse().unwrap(),
                &mut ctx,
            )
            .unwrap();

            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(key_id).unwrap().clone()
        }
    }

    type PostedUpgrades = Arc<Mutex<Option<Vec<OrganizationUserV2UpgradeRequestModel>>>>;

    /// Serves the pending list and records what is posted.
    fn mock_api(
        pending: Vec<OrganizationUserPendingV2UpgradeResponseModel>,
        posted: PostedUpgrades,
    ) -> impl FnOnce(&mut bitwarden_api_api::apis::ApiClientMock) {
        move |mock| {
            mock.organization_users_keys_api
                .expect_get_pending_v2_upgrades()
                .returning(move |_org| {
                    Ok(
                        OrganizationUserPendingV2UpgradeResponseModelListResponseModel {
                            object: None,
                            data: Some(pending.clone()),
                            continuation_token: None,
                        },
                    )
                })
                .once();
            mock.organization_users_keys_api
                .expect_post_v2_upgrades()
                .returning(move |_org, model| {
                    *posted.lock().unwrap() = Some(model.unwrap().upgrades);
                    Ok(())
                })
                .once();
        }
    }

    /// Answers `get_pending_v2_upgrades` with the given memberships, exactly once.
    fn expect_pending(
        mock: &mut bitwarden_api_api::apis::ApiClientMock,
        pending: Vec<OrganizationUserPendingV2UpgradeResponseModel>,
    ) {
        mock.organization_users_keys_api
            .expect_get_pending_v2_upgrades()
            .returning(move |_org| {
                Ok(
                    OrganizationUserPendingV2UpgradeResponseModelListResponseModel {
                        object: None,
                        data: Some(pending.clone()),
                        continuation_token: None,
                    },
                )
            })
            .once();
    }

    /// Answers `get_private_key` with the given wrapped key, exactly once.
    fn expect_get_private_key(mock: &mut bitwarden_api_api::apis::ApiClientMock, wrapped: String) {
        mock.organizations_api
            .expect_get_private_key()
            .returning(move |_org| {
                Ok(OrganizationPrivateKeyResponseModel {
                    object: None,
                    private_key: Some(wrapped.clone()),
                })
            })
            .once();
    }

    #[tokio::test]
    async fn test_pending_membership_is_posted_with_its_v2_user_key() {
        let posted: PostedUpgrades = Arc::default();

        // Built twice: the membership needs the key pair, the mock needs the membership.
        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (membership, expected_v2_user_key) = fixture.pending_membership();
        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, wrapped_private_key);
                        mock_api(vec![membership.clone()], posted.clone())(mock);
                    }),
                )),
            },
            ..fixture
        };

        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();

        let posted = posted
            .lock()
            .unwrap()
            .clone()
            .expect("an upgrade is posted");
        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(
            upgrade.organization_user_id,
            membership.organization_user_id.unwrap()
        );
        assert_eq!(upgrade.user_key_id, membership.user_key_id.clone().unwrap());
        assert_eq!(
            organization.decapsulate(upgrade.account_recovery_key.as_ref().unwrap()),
            expected_v2_user_key
        );
    }

    #[tokio::test]
    async fn test_no_pending_memberships_reads_no_private_key_and_posts_nothing() {
        let organization = TestOrganization::new(ApiClient::new_mocked(|mock| {
            mock.organization_users_keys_api
                .expect_get_pending_v2_upgrades()
                .returning(|_org| {
                    Ok(
                        OrganizationUserPendingV2UpgradeResponseModelListResponseModel {
                            object: None,
                            data: Some(vec![]),
                            continuation_token: None,
                        },
                    )
                })
                .once();
        }));

        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_membership_with_a_tampered_token_is_posted_without_an_account_recovery_key() {
        let posted: PostedUpgrades = Arc::default();

        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (mut tampered, _) = fixture.pending_membership();
        let (intact, expected_v2_user_key) = fixture.pending_membership();

        // An unrelated token's wrapped key, which this member's V1 user key cannot open.
        let (other, _) = fixture.pending_membership();
        tampered
            .v2_upgrade_token
            .as_mut()
            .unwrap()
            .wrapped_user_key2 = other
            .v2_upgrade_token
            .as_ref()
            .unwrap()
            .wrapped_user_key2
            .clone();

        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, wrapped_private_key);
                        mock_api(vec![tampered, intact.clone()], posted.clone())(mock);
                    }),
                )),
            },
            ..fixture
        };

        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();

        let posted = posted
            .lock()
            .unwrap()
            .clone()
            .expect("an upgrade is posted");
        let [tampered_upgrade, intact_upgrade] = posted.as_slice() else {
            panic!("both memberships are posted, got {}", posted.len());
        };
        assert_eq!(tampered_upgrade.account_recovery_key, None);
        assert_eq!(
            intact_upgrade.organization_user_id,
            intact.organization_user_id.unwrap()
        );
        assert_eq!(
            organization.decapsulate(intact_upgrade.account_recovery_key.as_ref().unwrap()),
            expected_v2_user_key
        );
    }

    #[tokio::test]
    async fn test_membership_with_a_malformed_account_recovery_key_is_posted_without_one() {
        let posted: PostedUpgrades = Arc::default();

        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (mut broken, _) = fixture.pending_membership();
        broken.account_recovery_key = Some("not an enc string".to_string());

        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, wrapped_private_key);
                        mock_api(vec![broken.clone()], posted.clone())(mock);
                    }),
                )),
            },
            ..fixture
        };

        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();

        let posted = posted
            .lock()
            .unwrap()
            .clone()
            .expect("an upgrade is posted");
        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.account_recovery_key, None);
    }

    /// The server cannot detect this, because the key id it checks is the one it reported.
    #[tokio::test]
    async fn test_membership_whose_token_does_not_match_its_key_id_is_posted_without_a_key() {
        let posted: PostedUpgrades = Arc::default();

        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (mut stale, _) = fixture.pending_membership();
        stale.user_key_id = Some(UNRELATED_USER_KEY_ID.to_string());

        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, wrapped_private_key);
                        mock_api(vec![stale.clone()], posted.clone())(mock);
                    }),
                )),
            },
            ..fixture
        };

        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();

        let posted = posted
            .lock()
            .unwrap()
            .clone()
            .expect("an upgrade is posted");
        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.user_key_id, UNRELATED_USER_KEY_ID);
        assert_eq!(upgrade.account_recovery_key, None);
    }

    #[tokio::test]
    async fn test_membership_without_a_user_key_id_is_skipped_and_nothing_is_posted() {
        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (mut unidentified, _) = fixture.pending_membership();
        unidentified.user_key_id = None;

        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, wrapped_private_key);
                        expect_pending(mock, vec![unidentified]);
                    }),
                )),
            },
            ..fixture
        };

        // The mock declares no `post_v2_upgrades`, so posting would fail the test.
        organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await
            .unwrap();
    }

    /// A private key the organization key cannot unwrap.
    #[tokio::test]
    async fn test_unusable_organization_private_key_is_an_error() {
        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (membership, _) = fixture.pending_membership();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        expect_get_private_key(mock, "not an enc string".to_string());
                        expect_pending(mock, vec![membership]);
                    }),
                )),
            },
            ..fixture
        };

        let result = organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::Crypto(
                OrganizationPrivateKeyError::InvalidPrivateKey
            ))
        ));
    }

    #[tokio::test]
    async fn test_absent_organization_private_key_is_an_error() {
        let fixture = TestOrganization::new(ApiClient::new_mocked(|_| {}));
        let (membership, _) = fixture.pending_membership();
        let organization = TestOrganization {
            client: OrganizationUsersManagementClient {
                key_store: fixture.client.key_store.clone(),
                api_configurations: Arc::new(ApiConfigurations::from_api_client(
                    ApiClient::new_mocked(|mock| {
                        mock.organizations_api
                            .expect_get_private_key()
                            .returning(|_org| {
                                Ok(OrganizationPrivateKeyResponseModel {
                                    object: None,
                                    private_key: None,
                                })
                            })
                            .once();
                        expect_pending(mock, vec![membership]);
                    }),
                )),
            },
            ..fixture
        };

        let result = organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn test_a_failed_pending_request_is_an_error() {
        let organization = TestOrganization::new(ApiClient::new_mocked(|mock| {
            mock.organization_users_keys_api
                .expect_get_pending_v2_upgrades()
                .returning(|_org| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                        "connection reset",
                    )))
                })
                .once();
        }));

        let result = organization
            .client
            .upgrade_pending_account_recovery_keys(organization.organization_id)
            .await;

        assert!(matches!(result, Err(AccountRecoveryV2UpgradeError::Api(_))));
    }

    #[tokio::test]
    async fn test_organization_without_a_key_in_the_key_store_is_an_error() {
        let organization = TestOrganization::new(ApiClient::new_mocked(|_| {}));

        let result = organization
            .client
            .upgrade_pending_account_recovery_keys(OrganizationId::new_v4())
            .await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::OrganizationKeyMissing)
        ));
    }

    #[test]
    fn test_administering_needs_both_permissions_and_an_unlocked_organization_key() {
        let organization = TestOrganization::new(ApiClient::new_mocked(|_| {}));

        assert!(organization.client.can_administer_account_recovery_keys(
            organization.organization_id,
            &OrganizationUserType::Owner,
            &Permissions::default()
        ));
        // Same role, an organization whose key this account does not hold.
        assert!(!organization.client.can_administer_account_recovery_keys(
            OrganizationId::new_v4(),
            &OrganizationUserType::Owner,
            &Permissions::default()
        ));
        // Organization key present, permissions absent.
        assert!(!organization.client.can_administer_account_recovery_keys(
            organization.organization_id,
            &OrganizationUserType::User,
            &Permissions::default()
        ));
    }

    #[test]
    fn test_owners_and_admins_hold_account_recovery_permissions() {
        for user_type in [OrganizationUserType::Owner, OrganizationUserType::Admin] {
            assert!(has_account_recovery_permissions(
                &user_type,
                &Permissions::default()
            ));
        }
    }

    #[test]
    fn test_custom_members_need_both_account_recovery_and_user_management() {
        let permissions = |manage_reset_password, manage_users| Permissions {
            manage_reset_password,
            manage_users,
            ..Permissions::default()
        };

        assert!(has_account_recovery_permissions(
            &OrganizationUserType::Custom,
            &permissions(true, true)
        ));
        for missing in [
            permissions(true, false),
            permissions(false, true),
            permissions(false, false),
        ] {
            assert!(!has_account_recovery_permissions(
                &OrganizationUserType::Custom,
                &missing
            ));
        }
    }

    #[test]
    fn test_plain_members_cannot_administer_account_recovery_keys() {
        assert!(!has_account_recovery_permissions(
            &OrganizationUserType::User,
            &Permissions {
                manage_reset_password: true,
                manage_users: true,
                ..Permissions::default()
            }
        ));
    }
}
