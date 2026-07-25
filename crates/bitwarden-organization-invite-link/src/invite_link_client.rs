use std::sync::Arc;

use bitwarden_api_api::models::{
    AcceptOrganizationInviteLinkRequestModel, ConfirmOrganizationInviteLinkRequestModel,
    CreateOrganizationInviteLinkRequestModel, GetOrganizationInviteRequestModel,
    RefreshOrganizationInviteLinkRequestModel, UpdateOrganizationInviteLinkRequestModel,
};
use bitwarden_core::{
    ApiError, Client, FromClient, MissingFieldError, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CoseKeyThumbprintExt, CryptoError, EncString, KeyStore, PrimitiveEncryptable, PublicKey,
    SpkiPublicKeyBytes, UnsignedSharedKey,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::invite::{Invite, InviteKeyBundleError, InviteSecret};
use http::StatusCode;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::organization_invite_link::OrganizationInviteLink;

/// Errors returned from [`InviteLinkClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum InviteLinkError {
    /// A cryptographic invite operation (creating, unsealing, or recovering the invite) failed.
    #[error(transparent)]
    Invite(#[from] InviteKeyBundleError),
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A low-level cryptographic operation (key wrapping, encapsulation, or public-key parsing)
    /// failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A required field was missing from a server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The account-recovery public key returned by the server does not match the organization
    /// public key bound into the invite.
    #[error("Account recovery public key does not match the invite's bound organization key")]
    RecoveryKeyMismatch,
}

/// Client for organization invite link cryptographic and network operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct InviteLinkClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl InviteLinkClient {
    /// Get an existing invite link.
    pub async fn get(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Option<OrganizationInviteLink>, InviteLinkError> {
        let response = match self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .get(organization_id.into())
            .await
            .map_err(ApiError::from)
        {
            Ok(response) => response,
            Err(ApiError::Response(rc)) if rc.status == StatusCode::NOT_FOUND => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        OrganizationInviteLink::try_from(response).map(Some)
    }

    /// Delete an existing invite link.
    pub async fn delete(&self, organization_id: OrganizationId) -> Result<(), InviteLinkError> {
        self.api_configurations
            .api_client
            .organization_invite_links_api()
            .delete(organization_id.into())
            .await
            .map_err(ApiError::from)?;
        Ok(())
    }

    /// Creates a new organization invite and posts it to the server, returning the full
    /// [`OrganizationInviteLink`] persisted by the server.
    ///
    /// # Security
    /// Only the sealed invite is posted to the server; the invite secret is never sent. Use
    /// [`InviteLinkClient::get_invite_secret`] to recover the secret needed to reconstruct the
    /// invite link.
    pub async fn make_invite_link(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        let invite = self.make_invite(organization_id).await?;

        let response = self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .create(
                organization_id.into(),
                Some(CreateOrganizationInviteLinkRequestModel {
                    allowed_domains,
                    invite: String::from(&invite),
                    supports_confirmation: invite.supports_confirmation(),
                }),
            )
            .await
            .map_err(ApiError::from)?;

        OrganizationInviteLink::try_from(response)
    }

    /// Refresh an existing invite link.
    /// This generates a new code and secret.
    pub async fn refresh_invite(
        &self,
        organization_id: OrganizationId,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        let invite = self.make_invite(organization_id).await?;

        let response = self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .refresh(
                organization_id.into(),
                Some(RefreshOrganizationInviteLinkRequestModel {
                    invite: String::from(&invite),
                    supports_confirmation: invite.supports_confirmation(),
                }),
            )
            .await
            .map_err(ApiError::from)?;

        OrganizationInviteLink::try_from(response)
    }

    /// Using the organization key, recovers the [`InviteSecret`] from the invite carried in the
    /// given [`OrganizationInviteLink`] so an admin can reconstruct the invite link.
    pub fn get_invite_secret(
        &self,
        organization_invite_link: OrganizationInviteLink,
    ) -> Result<InviteSecret, InviteLinkError> {
        let OrganizationInviteLink {
            organization_id,
            invite,
            ..
        } = organization_invite_link;

        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let invite_key = invite.unseal_invite_key_with_organization_key(org_key, &mut ctx)?;
        let invite_secret = invite.get_invite_secret(invite_key, &mut ctx)?;
        Ok(invite_secret)
    }

    /// Updates the allowed domains for an existing organization invite link.
    pub async fn update_allowed_domains(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        let response = self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .update(
                organization_id.into(),
                Some(UpdateOrganizationInviteLinkRequestModel { allowed_domains }),
            )
            .await
            .map_err(ApiError::from)?;

        OrganizationInviteLink::try_from(response)
    }

    /// Accepts an organization invite for the current user, optionally enrolling into account
    /// recovery (when `enroll_into_account_recovery` is set) and — when the invite supports
    /// confirmation — self-confirming.
    pub async fn accept_and_optionally_confirm(
        &self,
        organization_id: OrganizationId,
        code: String,
        invite_secret: InviteSecret,
        default_collection_name: String,
        enroll_into_account_recovery: bool,
    ) -> Result<(), InviteLinkError> {
        let code = uuid::Uuid::parse_str(&code).map_err(|_| MissingFieldError("code"))?;

        // When enrolling into account recovery, fetch the organization's public key (which is the
        // account-recovery public key) from the server.
        let recovery_public_key = if enroll_into_account_recovery {
            let response = self
                .api_configurations
                .api_client
                .organizations_api()
                .get_public_key(&organization_id.to_string())
                .await
                .map_err(ApiError::from)?;
            Some(
                require!(response.public_key)
                    .parse::<B64>()
                    .map_err(|_| MissingFieldError("public_key"))?,
            )
        } else {
            None
        };

        let invite_response = self
            .api_configurations
            .api_client
            .organization_users_api()
            .get_invite(Some(GetOrganizationInviteRequestModel {
                organization_id: organization_id.into(),
                code,
            }))
            .await
            .map_err(ApiError::from)?;

        let invite: Invite = require!(invite_response.invite).parse()?;

        // Confine the (non-Send) key store context to a synchronous scope; it produces the owned
        // request payload consumed after the `.await`s below.
        let request = {
            let mut ctx = self.key_store.context();

            // Recover the invite key from the invite secret the invitee holds.
            let invite_key =
                invite.unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)?;

            // Enroll into account recovery when requested. Verify the account-recovery public key
            // against the organization public-key thumbprint bound into the invite before
            // enrolling: a substituted recovery key would not match, so the organization key cannot
            // be captured by an attacker-supplied key. Then encapsulate the user key to it.
            let reset_password_key = match &recovery_public_key {
                Some(recovery_public_key) => {
                    let recovery_public_key =
                        PublicKey::from_der(&SpkiPublicKeyBytes::from(recovery_public_key))?;
                    let bound_thumbprint =
                        invite.get_public_key_thumbprint(invite_key, &mut ctx)?;
                    if bound_thumbprint != recovery_public_key.thumbprint()? {
                        return Err(InviteLinkError::RecoveryKeyMismatch);
                    }
                    Some(
                        UnsignedSharedKey::encapsulate(
                            SymmetricKeySlotId::User,
                            &recovery_public_key,
                            &ctx,
                        )?
                        .to_string(),
                    )
                }
                None => None,
            };

            if invite.supports_confirmation() {
                // Self-confirm: recover the organization key and encapsulate it to the user.
                let org_key = invite.unseal_organization_key(invite_key, &mut ctx)?;
                let user_public_key = ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)?;
                let org_user_key =
                    UnsignedSharedKey::encapsulate(org_key, &user_public_key, &ctx)?.to_string();
                let default_user_collection_name = default_collection_name
                    .encrypt(&mut ctx, org_key)?
                    .to_string();
                PendingPost::Confirm(ConfirmOrganizationInviteLinkRequestModel {
                    organization_id: organization_id.into(),
                    code,
                    org_user_key,
                    reset_password_key,
                    default_user_collection_name,
                })
            } else {
                PendingPost::Accept(AcceptOrganizationInviteLinkRequestModel {
                    organization_id: organization_id.into(),
                    code,
                    reset_password_key,
                })
            }
        };

        let organization_users_api = self.api_configurations.api_client.organization_users_api();
        match request {
            PendingPost::Confirm(model) => organization_users_api
                .confirm_invite_link(Some(model))
                .await
                .map_err(ApiError::from)?,
            PendingPost::Accept(model) => organization_users_api
                .accept_invite_link(Some(model))
                .await
                .map_err(ApiError::from)?,
        }

        Ok(())
    }

    /// Makes an invite blob to be included in a new invite link request.
    async fn make_invite(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Invite, InviteLinkError> {
        let wrapped_private_key_response = self
            .api_configurations
            .api_client
            .organizations_api()
            .get_private_key(organization_id.into())
            .await
            .map_err(ApiError::from)?;

        let wrapped_private_key: EncString =
            require!(wrapped_private_key_response.private_key).parse()?;

        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let (_, invite) = Invite::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)?;
        Ok(invite)
    }
}

/// A prepared invite acceptance request, built while the key store context is held and posted once
/// it has been dropped.
enum PendingPost {
    Confirm(ConfirmOrganizationInviteLinkRequestModel),
    Accept(AcceptOrganizationInviteLinkRequestModel),
}

/// Extension trait that exposes [`InviteLinkClient`] on [`Client`].
pub trait InviteLinkClientExt {
    /// Returns an [`InviteLinkClient`]
    fn invite_link(&self) -> InviteLinkClient;
}

impl InviteLinkClientExt for Client {
    fn invite_link(&self) -> InviteLinkClient {
        InviteLinkClient::from_client(self)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only injection point for [`InviteLinkClient::fetch_invite`]; see its `#[cfg(test)]`
    /// branch.
    static TEST_INVITE: std::cell::RefCell<Option<Invite>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{OrganizationInviteLinkResponseModel, OrganizationPublicKeyResponseModel},
    };
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{
        PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    };

    use super::*;

    fn make_client(org_id: OrganizationId, api_client: ApiClient) -> InviteLinkClient {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_and_org_key(user_key, org_id, org_key);
        // Give the store a user private key so the confirmation branch can derive a user public
        // key.
        {
            let mut ctx = key_store.context_mut();
            let local = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.persist_private_key(local, PrivateKeySlotId::UserPrivateKey)
                .expect("persisting the user private key should work");
        }
        InviteLinkClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    /// Serializes a fresh, valid [`Invite`] so response fixtures carry a parseable invite.
    fn valid_invite_string() -> String {
        let org_id = OrganizationId::new_v4();
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_and_org_key(user_key, org_id, org_key);
        let mut ctx = key_store.context();
        let slot = SymmetricKeySlotId::Organization(org_id);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped = ctx.wrap_private_key(slot, private_key).unwrap();
        let (_secret, invite) = Invite::make_for_private_key(slot, &wrapped, &mut ctx).unwrap();
        String::from(&invite)
    }

    /// Builds a well-formed invite-link response the "server" returns from `create`.
    fn create_response() -> OrganizationInviteLinkResponseModel {
        OrganizationInviteLinkResponseModel {
            object: None,
            id: Some(uuid::Uuid::new_v4()),
            code: Some(uuid::Uuid::new_v4()),
            organization_id: Some(uuid::Uuid::new_v4()),
            allowed_domains: Some(vec!["example.com".to_string()]),
            invite: Some(valid_invite_string()),
            supports_confirmation: Some(true),
            creation_date: Some("2025-01-10T00:00:00Z".to_string()),
        }
    }

    /// Mocks the invite-links API so `create` succeeds.
    fn mocked_create_ok() -> ApiClient {
        ApiClient::new_mocked(|mock| {
            mock.organization_invite_links_api
                .expect_create()
                .returning(|_org, _model| Ok(create_response()))
                .once();
        })
    }

    #[tokio::test]
    async fn make_invite_posts_and_returns_link() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id, mocked_create_ok());

        let link = client
            .make_invite_link(org_id, vec!["example.com".to_string()])
            .await
            .unwrap();

        assert!(link.supports_confirmation);
        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
    }

    #[tokio::test]
    async fn make_invite_two_calls_produce_different_invites() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|_org, _model| Ok(create_response()))
                    .times(2);
            }),
        );

        let link1 = client.make_invite_link(org_id, vec![]).await.unwrap();
        let link2 = client.make_invite_link(org_id, vec![]).await.unwrap();

        assert_ne!(String::from(&link1.invite), String::from(&link2.invite));
    }

    #[tokio::test]
    async fn make_invite_with_unknown_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id, ApiClient::new_mocked(|_| {}));

        let result = client.make_invite_link(other_org_id, vec![]).await;

        assert!(matches!(result, Err(InviteLinkError::Crypto(_))));
    }

    #[tokio::test]
    async fn make_invite_surfaces_api_errors() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|_org, _model| Err(std::io::Error::other("boom").into()));
            }),
        );

        let result = client.make_invite_link(org_id, vec![]).await;

        assert!(matches!(result, Err(InviteLinkError::Api(_))));
    }

    #[test]
    fn get_invite_secret_round_trips_to_the_invite_secret() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id, ApiClient::new_mocked(|_| {}));

        // Build an invite bound to the client's org key, wrapped in an `OrganizationInviteLink`;
        // `get_invite_secret` must recover a non-empty secret from it via the organization key.
        let invite = {
            let mut ctx = client.key_store.context();
            let org_key = SymmetricKeySlotId::Organization(org_id);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            let wrapped = ctx.wrap_private_key(org_key, private_key).unwrap();
            let (_secret, invite) =
                Invite::make_for_private_key(org_key, &wrapped, &mut ctx).unwrap();
            invite
        };
        let link = OrganizationInviteLink {
            id: uuid::Uuid::new_v4(),
            code: uuid::Uuid::new_v4(),
            organization_id: org_id,
            allowed_domains: vec![],
            invite,
            supports_confirmation: true,
            creation_date: "2025-01-10T00:00:00Z".parse().unwrap(),
        };

        let secret = client.get_invite_secret(link).unwrap();
        assert!(!String::from(&secret).is_empty());
    }

    /// Builds an invite + its secret and the organization public key it binds, all consistent with
    /// the client's org key, and pins the invite as the one the "server" returns.
    fn pin_invite(client: &InviteLinkClient, org_id: OrganizationId) -> (InviteSecret, B64) {
        let (secret, invite, org_public_key) = {
            let mut ctx = client.key_store.context();
            let org_key = SymmetricKeySlotId::Organization(org_id);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            let org_public_key = B64::from(
                ctx.get_public_key(private_key)
                    .unwrap()
                    .to_der()
                    .unwrap()
                    .as_ref(),
            );
            let wrapped = ctx.wrap_private_key(org_key, private_key).unwrap();
            let (secret, invite) =
                Invite::make_for_private_key(org_key, &wrapped, &mut ctx).unwrap();
            (secret, invite, org_public_key)
        };
        assert!(invite.supports_confirmation());
        TEST_INVITE.with(|slot| *slot.borrow_mut() = Some(invite));
        (secret, org_public_key)
    }

    #[tokio::test]
    async fn accept_and_confirm_succeeds_for_confirmable_invite() {
        let org_id = OrganizationId::new_v4();
        // `get_public_key` returns the base64 key held in this cell, filled after the invite is
        // generated below.
        let recovery = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = recovery.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_public_key()
                    .returning(move |_id| {
                        Ok(OrganizationPublicKeyResponseModel {
                            object: None,
                            public_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_confirm_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        let (secret, org_public_key) = pin_invite(&client, org_id);
        // The recovery public key returned by the "server" matches the invite's bound org key.
        *recovery.lock().unwrap() = Some(String::from(&org_public_key));

        client
            .accept_and_optionally_confirm(
                org_id,
                uuid::Uuid::new_v4().to_string(),
                secret,
                "Default".to_string(),
                true,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn accept_without_enrollment_confirms_without_recovery_key() {
        let org_id = OrganizationId::new_v4();
        // Without enrollment the recovery key is never fetched, so only `confirm_invite_link` runs.
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organization_users_api
                    .expect_confirm_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        let (secret, _org_public_key) = pin_invite(&client, org_id);
        client
            .accept_and_optionally_confirm(
                org_id,
                uuid::Uuid::new_v4().to_string(),
                secret,
                "Default".to_string(),
                false,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn accept_without_confirmation_posts_acceptance() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organization_users_api
                    .expect_accept_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        // An invite with confirmation disabled routes to the acceptance branch.
        let (secret, mut invite) = {
            let mut ctx = client.key_store.context();
            let org_key = SymmetricKeySlotId::Organization(org_id);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            let wrapped = ctx.wrap_private_key(org_key, private_key).unwrap();
            Invite::make_for_private_key(org_key, &wrapped, &mut ctx).unwrap()
        };
        invite.disable_confirmation();
        assert!(!invite.supports_confirmation());
        TEST_INVITE.with(|slot| *slot.borrow_mut() = Some(invite));

        client
            .accept_and_optionally_confirm(
                org_id,
                uuid::Uuid::new_v4().to_string(),
                secret,
                "Default".to_string(),
                false,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn accept_with_mismatched_recovery_key_fails() {
        let org_id = OrganizationId::new_v4();
        let recovery = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = recovery.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_public_key()
                    .returning(move |_id| {
                        Ok(OrganizationPublicKeyResponseModel {
                            object: None,
                            public_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
            }),
        );

        let (secret, _org_public_key) = pin_invite(&client, org_id);
        // The "server" returns an unrelated public key that must not match the invite's bound
        // thumbprint.
        let unrelated_public_key = {
            let mut ctx = client.key_store.context();
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            B64::from(
                ctx.get_public_key(private_key)
                    .unwrap()
                    .to_der()
                    .unwrap()
                    .as_ref(),
            )
        };
        *recovery.lock().unwrap() = Some(String::from(&unrelated_public_key));

        let result = client
            .accept_and_optionally_confirm(
                org_id,
                uuid::Uuid::new_v4().to_string(),
                secret,
                "Default".to_string(),
                true,
            )
            .await;

        assert!(matches!(result, Err(InviteLinkError::RecoveryKeyMismatch)));
    }
}
