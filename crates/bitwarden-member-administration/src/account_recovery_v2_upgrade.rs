//! Updating members' account recovery keys after their V1 to V2 upgrade.
//!
//! A V1 to V2 upgrade rotation does not re-encapsulate the member's account recovery key, because
//! that requires trusting a server-supplied organization public key and the upgrade shows the
//! member no prompt. The rotation writes a V2 upgrade token to the membership instead, and the
//! organization keeps an account recovery key that wraps the member's V1 user key.
//!
//! The token carries both user keys, each one wrapped with the other, so opening the V1 user key
//! yields the V2 one:
//!
//! ```text
//! OrganizationPrivateKey -> AccountRecovery       -> V1 user key
//! V1 user key            -> V2UpgradeToken        -> V2 user key
//! V2 user key            +  OrganizationPublicKey -> new AccountRecovery
//! ```
//!
//! An owner or admin runs
//! [`OrganizationUsersManagementClient::upgrade_pending_account_recovery_keys`]
//! for each organization whose key it holds. The server returns the pending memberships one page
//! at a time. The client sends the upgrades of each page to the server before it reads the next
//! page. For each membership, the client:
//!
//! 1. decapsulates the stored account recovery key into the member's V1 user key,
//! 2. unwraps the V2 user key from the upgrade token, which cross-validates both halves,
//! 3. compares the key id of that user key with the one the server reported,
//! 4. encapsulates the V2 user key to the organization.
//!
//! Steps 3 and 4 are [`AccountRecovery::make_after_v2_upgrade`].
//!
//! The server reports the user key id and can name any key. It holds none of the member's user
//! keys, so step 3 takes the key id of the user key the client recovered and compares it against
//! the reported one. A mismatch means the membership names a user key the upgrade token does not
//! carry.
//!
//! A membership is sent to the server without a key when its account recovery key or upgrade token
//! is missing, malformed, does not decrypt, or carries a user key other than the reported one.
//! That unenrolls the member from account recovery and drops a key that no longer opens the
//! member's vault. A retry would read the same keys and fail again, so the membership would
//! otherwise stay pending on every run. A membership that fails for any other reason is not sent
//! and stays pending.

use bitwarden_api_api::models::{
    OrganizationUserPendingV2UpgradeResponseModel, OrganizationUserV2UpgradeRequestModel,
    OrganizationUserV2UpgradesRequestModel,
};
use bitwarden_core::{
    ApiError, MissingFieldError, OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId, V2UpgradeToken},
    require,
};
use bitwarden_crypto::{EncString, KeyId, KeyStoreContext, PublicKey};
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{
    account_recovery::{AccountRecovery, AccountRecoveryMakeAfterV2UpgradeError},
    organization_private_key::OrganizationPrivateKey,
};
use bitwarden_organizations::OrganizationUserType;
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;
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
    /// The server returned a continuation token that is not a UUID.
    #[error("The continuation token is malformed")]
    MalformedContinuationToken,
    /// The organization key is not in the key store.
    #[error("The organization key is not available")]
    OrganizationKeyMissing,
    /// The wrapped private key from the server is corrupted, in no format this client knows, or was
    /// wrapped with an organization key other than the one this client holds.
    #[error("The organization's private key could not be unwrapped with the organization key")]
    OrganizationPrivateKeyUnwrapFailed,
}

/// Errors that stop one pending membership from being upgraded. They do not fail the
/// organization's upgrade: the membership is either unenrolled from account recovery or left
/// pending.
#[derive(Debug, Error)]
enum PendingMembershipError {
    /// The server could not parse the membership's stored upgrade token, so the token holds no
    /// usable V2 user key.
    #[error("The membership has no upgrade token")]
    MissingUpgradeToken,
    /// The upgrade token in the response is missing a wrapped user key, or a wrapped user key could
    /// not be parsed.
    #[error("The upgrade token is malformed")]
    MalformedUpgradeToken,
    /// The account recovery key is in no format this client knows, for example because it is
    /// corrupted.
    #[error("The account recovery key is malformed")]
    MalformedAccountRecoveryKey,
    /// The account recovery key was encapsulated to a different organization key pair, or is
    /// corrupted.
    #[error(
        "The account recovery key could not be decapsulated with the organization's private key"
    )]
    AccountRecoveryKeyDecapsulationFailed,
    /// The upgrade token was created with a V1 user key other than the one in the account recovery
    /// key, holds a wrapped user key in no known format, or was tampered with.
    #[error("The upgrade token could not be unwrapped with the member's V1 user key")]
    UpgradeTokenUnwrapFailed,
    /// The server reported a key id in no format this client knows.
    #[error("The membership's user key id is malformed")]
    MalformedUserKeyId,
    /// The V2 user key could not be made into an account recovery key.
    #[error(transparent)]
    MakeAfterV2UpgradeFailed(AccountRecoveryMakeAfterV2UpgradeError),
}

/// Whether the account's role lets it read the organization's private key and set members'
/// account recovery keys. The server accepts only owners and admins.
fn has_account_recovery_permissions(user_type: &OrganizationUserType) -> bool {
    matches!(
        user_type,
        OrganizationUserType::Owner | OrganizationUserType::Admin
    )
}

impl OrganizationUsersManagementClient {
    /// Whether the account can update the account recovery keys of this organization's members.
    ///
    /// The account must be an owner or an admin. It must also hold the organization key, which
    /// unwraps the organization's private key.
    pub fn can_administer_account_recovery_keys(
        &self,
        organization_id: OrganizationId,
        user_type: &OrganizationUserType,
    ) -> bool {
        has_account_recovery_permissions(user_type)
            && self
                .key_store
                .context()
                .has_symmetric_key(SymmetricKeySlotId::Organization(organization_id))
    }

    /// Reads the organization's private key, wrapped with the organization key.
    ///
    /// The server requires the ManageUsers permission, which owners and admins always have, so
    /// this request does not fail authorization for the roles that run the upgrade.
    async fn wrapped_organization_private_key(
        &self,
        organization_id: OrganizationId,
    ) -> Result<EncString, AccountRecoveryV2UpgradeError> {
        Ok(EncString::from(require!(
            self.api_configurations
                .api_client
                .organizations_api()
                .get_private_key(organization_id.into())
                .await?
                .private_key
        )))
    }

    /// Builds the request entries for one page of pending memberships.
    fn upgrade_requests(
        &self,
        organization_id: OrganizationId,
        wrapped_private_key: &EncString,
        pending: &[OrganizationUserPendingV2UpgradeResponseModel],
    ) -> Result<Vec<OrganizationUserV2UpgradeRequestModel>, AccountRecoveryV2UpgradeError> {
        // Unwrapped once per page: the key store has no persistent slot for the organization's
        // private key, so it lives in this context, and a context must not be held across an
        // await.
        let mut ctx = self.key_store.context();
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            SymmetricKeySlotId::Organization(organization_id),
            wrapped_private_key,
            &mut ctx,
        )
        .map_err(|_| AccountRecoveryV2UpgradeError::OrganizationPrivateKeyUnwrapFailed)?;
        let organization_public_key = organization_private_key
            .public_key(&ctx)
            .map_err(|_| AccountRecoveryV2UpgradeError::OrganizationPrivateKeyUnwrapFailed)?;

        Ok(pending
            .iter()
            .filter_map(|membership| {
                let organization_user_id = membership.organization_user_id;
                let account_recovery_key = match account_recovery_key(
                    &organization_private_key,
                    &organization_public_key,
                    membership,
                    &mut ctx,
                ) {
                    Ok(key) => Some(key),
                    Err(
                        e @ (PendingMembershipError::MissingUpgradeToken
                        | PendingMembershipError::MalformedUpgradeToken
                        | PendingMembershipError::MalformedAccountRecoveryKey
                        | PendingMembershipError::AccountRecoveryKeyDecapsulationFailed
                        | PendingMembershipError::UpgradeTokenUnwrapFailed
                        | PendingMembershipError::MakeAfterV2UpgradeFailed(
                            AccountRecoveryMakeAfterV2UpgradeError::UserKeyIdMismatch,
                        )),
                    ) => {
                        // Left pending, the membership would fail the same way on every run,
                        // because a retry reads the same keys.
                        warn!(
                            %organization_id,
                            %organization_user_id,
                            "Unenrolling a member from account recovery: {e}"
                        );
                        None
                    }
                    Err(
                        e @ (PendingMembershipError::MalformedUserKeyId
                        | PendingMembershipError::MakeAfterV2UpgradeFailed(
                            AccountRecoveryMakeAfterV2UpgradeError::MissingMemberUserKey
                            | AccountRecoveryMakeAfterV2UpgradeError::MemberUserKeyNotV2
                            | AccountRecoveryMakeAfterV2UpgradeError::Make(_),
                        )),
                    ) => {
                        // A malformed key id is not unenrolled: unenrolling also sends the key id,
                        // and one malformed entry fails the whole request. The other errors are not
                        // unenrolled either: the upgrade token already yielded a V2 user key, so
                        // they happen in this client, not in the membership's keys, and a later run
                        // can succeed.
                        warn!(
                            %organization_id,
                            %organization_user_id,
                            "Leaving a membership pending: {e}"
                        );
                        return None;
                    }
                };

                // The key id is sent back unchanged, because the server checks it against the
                // member's user row.
                let mut upgrade = OrganizationUserV2UpgradeRequestModel::new(
                    organization_user_id,
                    membership.user_key_id.clone(),
                );
                upgrade.account_recovery_key = account_recovery_key;
                Some(upgrade)
            })
            .collect())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersManagementClient {
    /// Re-encapsulates the account recovery keys of members who have upgraded to a V2 user key.
    ///
    /// A membership whose account recovery key or upgrade token is malformed or fails to decrypt
    /// is sent to the server without a key. That unenrolls the member from account recovery and
    /// drops a key that no longer opens the member's vault.
    ///
    /// Callers that filter a list of organizations should check
    /// `can_administer_account_recovery_keys` first.
    pub async fn upgrade_pending_account_recovery_keys(
        &self,
        organization_id: OrganizationId,
    ) -> Result<(), AccountRecoveryV2UpgradeError> {
        if !self
            .key_store
            .context()
            .has_symmetric_key(SymmetricKeySlotId::Organization(organization_id))
        {
            return Err(AccountRecoveryV2UpgradeError::OrganizationKeyMissing);
        }

        let api = self
            .api_configurations
            .api_client
            .organization_users_keys_api();
        let mut continuation_token = None;
        // Read on the first page that has pending memberships, so most runs skip the request.
        let mut wrapped_private_key = None;

        loop {
            let page = api
                .get_pending_v2_upgrades(organization_id.into(), continuation_token)
                .await?;
            let pending = page.data.unwrap_or_default();

            if !pending.is_empty() {
                let wrapped_private_key = match &wrapped_private_key {
                    Some(key) => key,
                    None => wrapped_private_key.insert(
                        self.wrapped_organization_private_key(organization_id)
                            .await?,
                    ),
                };
                let upgrades =
                    self.upgrade_requests(organization_id, wrapped_private_key, &pending)?;

                if !upgrades.is_empty() {
                    api.post_v2_upgrades(
                        organization_id.into(),
                        Some(OrganizationUserV2UpgradesRequestModel::new(upgrades)),
                    )
                    .await?;
                }
            }

            let Some(next) = page.continuation_token else {
                return Ok(());
            };
            continuation_token = Some(
                next.parse::<Uuid>()
                    .map_err(|_| AccountRecoveryV2UpgradeError::MalformedContinuationToken)?,
            );
        }
    }
}

/// Reads the V2 user key out of the membership's upgrade token and encapsulates it to the
/// organization as the member's new account recovery key.
fn account_recovery_key(
    organization_private_key: &OrganizationPrivateKey<KeySlotIds>,
    organization_public_key: &PublicKey,
    membership: &OrganizationUserPendingV2UpgradeResponseModel,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<String, PendingMembershipError> {
    let user_key_id: KeyId = membership
        .user_key_id
        .parse()
        .map_err(|_| PendingMembershipError::MalformedUserKeyId)?;
    let upgrade_token = V2UpgradeToken::try_from(
        membership
            .v2_upgrade_token
            .as_deref()
            .ok_or(PendingMembershipError::MissingUpgradeToken)?,
    )
    .map_err(|_| PendingMembershipError::MalformedUpgradeToken)?;
    let account_recovery: AccountRecovery = membership
        .account_recovery_key
        .parse()
        .map_err(|_| PendingMembershipError::MalformedAccountRecoveryKey)?;

    let v1_user_key = account_recovery
        .unseal_member_user_key(organization_private_key, ctx)
        .map_err(|_| PendingMembershipError::AccountRecoveryKeyDecapsulationFailed)?;
    // Unwrapping cross-validates both halves of the token, so a tampered token fails here.
    let v2_user_key = upgrade_token
        .unwrap_v2(v1_user_key, ctx)
        .map_err(|_| PendingMembershipError::UpgradeTokenUnwrapFailed)?;

    // The key id is sent back to the server as it reported it, so the server's check against the
    // member's user row cannot detect a token carrying a different key.
    let account_recovery = AccountRecovery::make_after_v2_upgrade(
        v2_user_key,
        user_key_id,
        organization_private_key,
        organization_public_key,
        ctx,
    )
    .map_err(PendingMembershipError::MakeAfterV2UpgradeFailed)?;

    Ok(String::from(&account_recovery))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_api_api::{
        apis::{ApiClient, ApiClientMock},
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
        fn new() -> Self {
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
                    api_configurations: Arc::new(ApiConfigurations::from_api_client(
                        ApiClient::new_mocked(|_| {}),
                    )),
                },
                organization_id,
                wrapped_private_key,
            }
        }

        /// Replaces the API client. Memberships are built before the mock, because they need the
        /// organization's key pair.
        fn with_api(self, configure: impl FnOnce(&mut ApiClientMock)) -> Self {
            Self {
                client: OrganizationUsersManagementClient {
                    key_store: self.client.key_store,
                    api_configurations: Arc::new(ApiConfigurations::from_api_client(
                        ApiClient::new_mocked(configure),
                    )),
                },
                ..self
            }
        }

        async fn upgrade(&self) -> Result<(), AccountRecoveryV2UpgradeError> {
            self.client
                .upgrade_pending_account_recovery_keys(self.organization_id)
                .await
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

            let account_recovery = AccountRecovery::make(
                v1_user_key,
                &organization_private_key.public_key(&ctx).unwrap(),
                &organization_private_key.trust_proof(),
                &ctx,
            )
            .unwrap();

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
                    organization_user_id: Uuid::new_v4(),
                    user_key_id: user_key_id.to_string(),
                    account_recovery_key: String::from(&account_recovery),
                    v2_upgrade_token: Some(Box::new(V2UpgradeTokenResponseModel {
                        wrapped_user_key1: Some(token.wrapped_user_key_1.to_string()),
                        wrapped_user_key2: Some(token.wrapped_user_key_2.to_string()),
                    })),
                },
                expected,
            )
        }

        /// Runs `account_recovery_key` for one membership with this organization's key pair.
        fn account_recovery_key(
            &self,
            membership: &OrganizationUserPendingV2UpgradeResponseModel,
        ) -> Result<String, PendingMembershipError> {
            let mut ctx = self.client.key_store.context();
            let organization_private_key = self.organization_private_key(&mut ctx);
            let organization_public_key = organization_private_key.public_key(&ctx).unwrap();
            account_recovery_key(
                &organization_private_key,
                &organization_public_key,
                membership,
                &mut ctx,
            )
        }

        /// Decapsulates a posted account recovery key.
        fn decapsulate(&self, account_recovery_key: &str) -> SymmetricCryptoKey {
            let mut ctx = self.client.key_store.context();
            let organization_private_key = self.organization_private_key(&mut ctx);
            let key_id = account_recovery_key
                .parse::<AccountRecovery>()
                .unwrap()
                .unseal_member_user_key(&organization_private_key, &mut ctx)
                .unwrap();

            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(key_id).unwrap().clone()
        }
    }

    /// The upgrades of every POST, in order.
    type PostedPages = Arc<Mutex<Vec<Vec<OrganizationUserV2UpgradeRequestModel>>>>;

    /// Answers `get_pending_v2_upgrades` for `continuation_token` with one page, exactly once.
    fn expect_page(
        mock: &mut ApiClientMock,
        continuation_token: Option<Uuid>,
        pending: Vec<OrganizationUserPendingV2UpgradeResponseModel>,
        next: Option<String>,
    ) {
        mock.organization_users_keys_api
            .expect_get_pending_v2_upgrades()
            .withf(move |_org, token| *token == continuation_token)
            .returning(move |_org, _token| {
                Ok(
                    OrganizationUserPendingV2UpgradeResponseModelListResponseModel {
                        object: None,
                        data: Some(pending.clone()),
                        continuation_token: next.clone(),
                    },
                )
            })
            .once();
    }

    /// Answers `get_pending_v2_upgrades` with a single page.
    fn expect_pending(
        mock: &mut ApiClientMock,
        pending: Vec<OrganizationUserPendingV2UpgradeResponseModel>,
    ) {
        expect_page(mock, None, pending, None);
    }

    /// Records every `post_v2_upgrades` call.
    fn expect_posts(mock: &mut ApiClientMock, posted: PostedPages) {
        mock.organization_users_keys_api
            .expect_post_v2_upgrades()
            .returning(move |_org, model| {
                posted.lock().unwrap().push(model.unwrap().upgrades);
                Ok(())
            });
    }

    /// Answers `get_private_key` with the given wrapped key, exactly once.
    fn expect_get_private_key(mock: &mut ApiClientMock, wrapped: String) {
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

    /// Runs the upgrade over a single page and returns the upgrades of the one POST.
    async fn upgrade_single_page(
        fixture: TestOrganization,
        pending: Vec<OrganizationUserPendingV2UpgradeResponseModel>,
    ) -> (TestOrganization, Vec<OrganizationUserV2UpgradeRequestModel>) {
        let posted: PostedPages = Arc::default();
        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = fixture.with_api(|mock| {
            expect_get_private_key(mock, wrapped_private_key);
            expect_pending(mock, pending);
            expect_posts(mock, posted.clone());
        });

        organization.upgrade().await.unwrap();

        let mut posted = posted.lock().unwrap().clone();
        assert_eq!(posted.len(), 1, "exactly one page is posted");
        (organization, posted.remove(0))
    }

    #[tokio::test]
    async fn test_pending_membership_is_posted_with_its_v2_user_key() {
        let fixture = TestOrganization::new();
        let (membership, expected_v2_user_key) = fixture.pending_membership();

        let (organization, posted) = upgrade_single_page(fixture, vec![membership.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(
            upgrade.organization_user_id,
            membership.organization_user_id
        );
        assert_eq!(upgrade.user_key_id, membership.user_key_id);
        assert_eq!(
            organization.decapsulate(upgrade.account_recovery_key.as_ref().unwrap()),
            expected_v2_user_key
        );
    }

    #[tokio::test]
    async fn test_no_pending_memberships_reads_no_private_key_and_posts_nothing() {
        let organization = TestOrganization::new().with_api(|mock| expect_pending(mock, vec![]));

        organization.upgrade().await.unwrap();
    }

    #[tokio::test]
    async fn test_each_page_is_posted_and_the_next_page_is_read_with_its_continuation_token() {
        let posted: PostedPages = Arc::default();

        let fixture = TestOrganization::new();
        let (first, _) = fixture.pending_membership();
        let (second, _) = fixture.pending_membership();
        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let next = first.organization_user_id;
        let organization = fixture.with_api(|mock| {
            expect_get_private_key(mock, wrapped_private_key);
            expect_page(mock, None, vec![first.clone()], Some(next.to_string()));
            expect_page(mock, Some(next), vec![second.clone()], None);
            expect_posts(mock, posted.clone());
        });

        organization.upgrade().await.unwrap();

        let posted_ids = posted
            .lock()
            .unwrap()
            .iter()
            .map(|page| {
                page.iter()
                    .map(|upgrade| upgrade.organization_user_id)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            posted_ids,
            vec![
                vec![first.organization_user_id],
                vec![second.organization_user_id]
            ]
        );
    }

    #[tokio::test]
    async fn test_empty_page_with_a_continuation_token_is_not_posted_and_the_next_page_is_read() {
        let posted: PostedPages = Arc::default();

        let fixture = TestOrganization::new();
        let (membership, _) = fixture.pending_membership();
        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let next = Uuid::new_v4();
        let organization = fixture.with_api(|mock| {
            expect_get_private_key(mock, wrapped_private_key);
            expect_page(mock, None, vec![], Some(next.to_string()));
            expect_page(mock, Some(next), vec![membership.clone()], None);
            expect_posts(mock, posted.clone());
        });

        organization.upgrade().await.unwrap();

        let posted = posted.lock().unwrap().clone();
        let [page] = posted.as_slice() else {
            panic!("exactly one page is posted, got {}", posted.len());
        };
        let [upgrade] = page.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", page.len());
        };
        assert_eq!(
            upgrade.organization_user_id,
            membership.organization_user_id
        );
    }

    #[tokio::test]
    async fn test_malformed_continuation_token_is_an_error() {
        let organization = TestOrganization::new().with_api(|mock| {
            expect_page(mock, None, vec![], Some("not a uuid".to_string()));
        });

        let result = organization.upgrade().await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::MalformedContinuationToken)
        ));
    }

    #[tokio::test]
    async fn test_membership_without_an_upgrade_token_is_posted_without_an_account_recovery_key() {
        let fixture = TestOrganization::new();
        let (mut unparsed, _) = fixture.pending_membership();
        unparsed.v2_upgrade_token = None;

        let (_, posted) = upgrade_single_page(fixture, vec![unparsed.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.organization_user_id, unparsed.organization_user_id);
        assert_eq!(upgrade.user_key_id, unparsed.user_key_id);
        assert_eq!(upgrade.account_recovery_key, None);
    }

    #[tokio::test]
    async fn test_membership_with_an_unparseable_upgrade_token_is_posted_without_an_account_recovery_key()
     {
        let fixture = TestOrganization::new();
        let (mut unparseable, _) = fixture.pending_membership();
        unparseable.v2_upgrade_token = Some(Box::new(V2UpgradeTokenResponseModel {
            wrapped_user_key1: Some("not an enc string".to_string()),
            wrapped_user_key2: None,
        }));

        let (_, posted) = upgrade_single_page(fixture, vec![unparseable.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(
            upgrade.organization_user_id,
            unparseable.organization_user_id
        );
        assert_eq!(upgrade.account_recovery_key, None);
    }

    #[tokio::test]
    async fn test_membership_with_a_tampered_token_is_posted_without_an_account_recovery_key() {
        let fixture = TestOrganization::new();
        let (mut tampered, _) = fixture.pending_membership();
        let (intact, expected_v2_user_key) = fixture.pending_membership();

        // An unrelated token's wrapped key, which this member's V1 user key cannot open.
        let (other, _) = fixture.pending_membership();
        tampered
            .v2_upgrade_token
            .as_mut()
            .unwrap()
            .wrapped_user_key2 = other.v2_upgrade_token.unwrap().wrapped_user_key2;

        let (organization, posted) =
            upgrade_single_page(fixture, vec![tampered, intact.clone()]).await;

        let [tampered_upgrade, intact_upgrade] = posted.as_slice() else {
            panic!("both memberships are posted, got {}", posted.len());
        };
        assert_eq!(tampered_upgrade.account_recovery_key, None);
        assert_eq!(
            intact_upgrade.organization_user_id,
            intact.organization_user_id
        );
        assert_eq!(
            organization.decapsulate(intact_upgrade.account_recovery_key.as_ref().unwrap()),
            expected_v2_user_key
        );
    }

    #[tokio::test]
    async fn test_membership_with_a_malformed_account_recovery_key_is_posted_without_one() {
        let fixture = TestOrganization::new();
        let (mut broken, _) = fixture.pending_membership();
        broken.account_recovery_key = "not an enc string".to_string();

        let (_, posted) = upgrade_single_page(fixture, vec![broken.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.organization_user_id, broken.organization_user_id);
        assert_eq!(upgrade.account_recovery_key, None);
    }

    /// The organization's private key cannot open a key encapsulated to another organization.
    #[tokio::test]
    async fn test_account_recovery_key_for_another_organization_is_posted_without_one() {
        let fixture = TestOrganization::new();
        let (mut foreign, _) = fixture.pending_membership();
        let (other_organization_membership, _) = TestOrganization::new().pending_membership();
        foreign.account_recovery_key = other_organization_membership.account_recovery_key;

        let (_, posted) = upgrade_single_page(fixture, vec![foreign.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.organization_user_id, foreign.organization_user_id);
        assert_eq!(upgrade.account_recovery_key, None);
    }

    /// The server cannot detect this, because the key id it checks is the one it reported.
    #[tokio::test]
    async fn test_membership_whose_token_does_not_match_its_key_id_is_posted_without_a_key() {
        let fixture = TestOrganization::new();
        let (mut stale, _) = fixture.pending_membership();
        stale.user_key_id = UNRELATED_USER_KEY_ID.to_string();

        let (_, posted) = upgrade_single_page(fixture, vec![stale.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.organization_user_id, stale.organization_user_id);
        assert_eq!(upgrade.user_key_id, UNRELATED_USER_KEY_ID);
        assert_eq!(upgrade.account_recovery_key, None);
    }

    /// The server rejects a whole request that carries a malformed key id.
    #[tokio::test]
    async fn test_membership_with_a_malformed_user_key_id_is_not_posted() {
        let fixture = TestOrganization::new();
        let (mut unparseable, _) = fixture.pending_membership();
        unparseable.user_key_id = "not a key id".to_string();
        let (intact, _) = fixture.pending_membership();

        let (_, posted) = upgrade_single_page(fixture, vec![unparseable, intact.clone()]).await;

        let [upgrade] = posted.as_slice() else {
            panic!("exactly one upgrade is posted, got {}", posted.len());
        };
        assert_eq!(upgrade.organization_user_id, intact.organization_user_id);
    }

    #[tokio::test]
    async fn test_page_whose_memberships_are_all_skipped_is_not_posted() {
        let fixture = TestOrganization::new();
        let (mut unparseable, _) = fixture.pending_membership();
        unparseable.user_key_id = "not a key id".to_string();
        let wrapped_private_key = fixture.wrapped_private_key.clone();
        let organization = fixture.with_api(|mock| {
            expect_get_private_key(mock, wrapped_private_key);
            expect_pending(mock, vec![unparseable]);
        });

        organization.upgrade().await.unwrap();
    }

    /// A private key the organization key cannot unwrap.
    #[tokio::test]
    async fn test_unusable_organization_private_key_is_an_error() {
        let fixture = TestOrganization::new();
        let (membership, _) = fixture.pending_membership();
        let organization = fixture.with_api(|mock| {
            expect_get_private_key(mock, "not an enc string".to_string());
            expect_pending(mock, vec![membership]);
        });

        let result = organization.upgrade().await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::OrganizationPrivateKeyUnwrapFailed)
        ));
    }

    #[tokio::test]
    async fn test_absent_organization_private_key_is_an_error() {
        let fixture = TestOrganization::new();
        let (membership, _) = fixture.pending_membership();
        let organization = fixture.with_api(|mock| {
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
        });

        let result = organization.upgrade().await;

        assert!(matches!(
            result,
            Err(AccountRecoveryV2UpgradeError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn test_a_failed_pending_request_is_an_error() {
        let organization = TestOrganization::new().with_api(|mock| {
            mock.organization_users_keys_api
                .expect_get_pending_v2_upgrades()
                .returning(|_org, _token| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                        "connection reset",
                    )))
                })
                .once();
        });

        let result = organization.upgrade().await;

        assert!(matches!(result, Err(AccountRecoveryV2UpgradeError::Api(_))));
    }

    #[tokio::test]
    async fn test_organization_without_a_key_in_the_key_store_is_an_error() {
        let organization = TestOrganization::new();

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
    fn test_membership_with_a_malformed_user_key_id_fails_with_malformed_user_key_id() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.user_key_id = "not a key id".to_string();

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::MalformedUserKeyId)
        ));
    }

    #[test]
    fn test_membership_without_an_upgrade_token_fails_with_missing_upgrade_token() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.v2_upgrade_token = None;

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::MissingUpgradeToken)
        ));
    }

    #[test]
    fn test_upgrade_token_without_a_wrapped_user_key_fails_with_malformed_upgrade_token() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership
            .v2_upgrade_token
            .as_mut()
            .unwrap()
            .wrapped_user_key1 = None;

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::MalformedUpgradeToken)
        ));
    }

    #[test]
    fn test_membership_with_an_unparseable_account_recovery_key_fails_with_malformed_account_recovery_key()
     {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.account_recovery_key = "not an enc string".to_string();

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::MalformedAccountRecoveryKey)
        ));
    }

    #[test]
    fn test_account_recovery_key_for_another_organization_fails_with_decapsulation_failed() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.account_recovery_key = TestOrganization::new()
            .pending_membership()
            .0
            .account_recovery_key;

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::AccountRecoveryKeyDecapsulationFailed)
        ));
    }

    #[test]
    fn test_upgrade_token_of_another_member_fails_with_upgrade_token_unwrap_failed() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.v2_upgrade_token = organization.pending_membership().0.v2_upgrade_token;

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::UpgradeTokenUnwrapFailed)
        ));
    }

    #[test]
    fn test_reported_key_id_of_another_key_fails_with_user_key_id_mismatch() {
        let organization = TestOrganization::new();
        let (mut membership, _) = organization.pending_membership();
        membership.user_key_id = UNRELATED_USER_KEY_ID.to_string();

        assert!(matches!(
            organization.account_recovery_key(&membership),
            Err(PendingMembershipError::MakeAfterV2UpgradeFailed(
                AccountRecoveryMakeAfterV2UpgradeError::UserKeyIdMismatch
            ))
        ));
    }

    #[test]
    fn test_administering_needs_an_administering_role_and_an_unlocked_organization_key() {
        let organization = TestOrganization::new();

        assert!(organization.client.can_administer_account_recovery_keys(
            organization.organization_id,
            &OrganizationUserType::Owner,
        ));
        // Same role, an organization whose key this account does not hold.
        assert!(!organization.client.can_administer_account_recovery_keys(
            OrganizationId::new_v4(),
            &OrganizationUserType::Owner,
        ));
        // Organization key present, role without account recovery permissions.
        assert!(!organization.client.can_administer_account_recovery_keys(
            organization.organization_id,
            &OrganizationUserType::User,
        ));
    }

    #[test]
    fn test_owners_and_admins_hold_account_recovery_permissions() {
        for user_type in [OrganizationUserType::Owner, OrganizationUserType::Admin] {
            assert!(has_account_recovery_permissions(&user_type));
        }
    }

    /// The server rejects custom members, whatever their permissions.
    #[test]
    fn test_custom_and_plain_members_cannot_administer_account_recovery_keys() {
        for user_type in [OrganizationUserType::Custom, OrganizationUserType::User] {
            assert!(!has_account_recovery_permissions(&user_type));
        }
    }
}
