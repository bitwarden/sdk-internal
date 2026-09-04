use std::sync::Arc;

use bitwarden_api_api::models::{
    AcceptOrganizationInviteLinkRequestModel, ConfirmOrganizationInviteLinkRequestModel,
    CreateOrganizationInviteLinkRequestModel, GetOrganizationInviteRequestModel,
    RefreshOrganizationInviteLinkRequestModel,
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
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::OrganizationInviteLink;

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
    /// A value was present but malformed and could not be parsed.
    #[error("Failed to parse `{0}`")]
    ParseFailure(&'static str),
    /// The account-recovery public key returned by the server does not match the organization
    /// public key bound into the invite.
    #[error("Account recovery public key does not match the invite's bound organization key")]
    RecoveryKeyMismatch,
}

/// Client for organization invite link cryptographic and network operations.
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct InviteLinkClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
impl InviteLinkClient {
    /// Creates a new organization invite and posts it to the server, returning the full
    /// [`OrganizationInviteLink`] persisted by the server.
    ///
    /// # Security
    /// Only the sealed invite is posted to the server; the invite secret is never sent. Use
    /// [`InviteLinkClient::get_invite_secret`] to recover the secret needed to reconstruct the
    /// invite link.
    pub async fn create_invite_link(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        let invite = self
            .make_invite(organization_id, supports_confirmation)
            .await?;

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
            .await?;

        OrganizationInviteLink::try_from(response)
    }

    /// Refresh an existing invite link.
    /// This generates a new code and secret.
    pub async fn refresh_invite_link(
        &self,
        organization_id: OrganizationId,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        let invite = self
            .make_invite(organization_id, supports_confirmation)
            .await?;

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
            .await?;

        OrganizationInviteLink::try_from(response)
    }

    /// Using the organization key, recovers the [`InviteSecret`] from the invite carried in the
    /// given [`OrganizationInviteLink`] so an admin can reconstruct the invite link.
    #[cfg_attr(feature = "wasm", wasm_bindgen(unchecked_return_type = "InviteSecret"))]
    pub fn get_invite_secret(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
    ) -> Result<InviteSecret, InviteLinkError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let invite_key = invite.unseal_invite_key_with_organization_key(org_key, &mut ctx)?;
        let invite_secret = invite.get_invite_secret(invite_key, &mut ctx)?;
        Ok(invite_secret)
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
        let code =
            uuid::Uuid::parse_str(&code).map_err(|_| InviteLinkError::ParseFailure("code"))?;

        // When enrolling into account recovery, fetch the organization's public key (which is the
        // account-recovery public key) from the server.
        let recovery_public_key = if enroll_into_account_recovery {
            let response = self
                .api_configurations
                .api_client
                .organizations_api()
                .get_public_key(&organization_id.to_string())
                .await?;
            Some(
                require!(response.public_key)
                    .parse::<B64>()
                    .map_err(|_| InviteLinkError::ParseFailure("public_key"))?,
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
            .await?;

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
            PendingPost::Confirm(model) => {
                organization_users_api
                    .confirm_invite_link(Some(model))
                    .await?
            }
            PendingPost::Accept(model) => {
                organization_users_api
                    .accept_invite_link(Some(model))
                    .await?
            }
        }

        Ok(())
    }

    /// Helper function to make a new Invite to be included in a request model.
    async fn make_invite(
        &self,
        organization_id: OrganizationId,
        supports_confirmation: bool,
    ) -> Result<Invite, InviteLinkError> {
        let wrapped_private_key_response = self
            .api_configurations
            .api_client
            .organizations_api()
            .get_private_key(organization_id.into())
            .await?;

        let wrapped_private_key: EncString =
            require!(wrapped_private_key_response.private_key).parse()?;

        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let (_, mut invite) =
            Invite::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)?;

        // Invites support confirmation by default; disable if not applicable
        if !supports_confirmation {
            invite.disable_confirmation();
        }

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
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            OrganizationInviteLinkResponseModel, OrganizationInviteResponseModel,
            OrganizationPrivateKeyResponseModel, OrganizationPublicKeyResponseModel,
        },
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

    /// Wraps a fresh private key under the client's organization key and returns the serialized
    /// [`EncString`], matching what the server's `get_private_key` endpoint would return.
    fn wrapped_org_private_key(client: &InviteLinkClient, org_id: OrganizationId) -> String {
        let mut ctx = client.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(org_id);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        ctx.wrap_private_key(org_key, private_key)
            .unwrap()
            .to_string()
    }

    /// Builds the response model an invite-links `create`/`refresh` endpoint would return, echoing
    /// the posted invite back so it can be parsed into an [`OrganizationInviteLink`].
    fn echo_link_response(
        org_id: uuid::Uuid,
        allowed_domains: Vec<String>,
        invite: String,
        supports_confirmation: bool,
    ) -> OrganizationInviteLinkResponseModel {
        OrganizationInviteLinkResponseModel {
            object: None,
            id: Some(uuid::Uuid::new_v4()),
            code: Some(uuid::Uuid::new_v4()),
            organization_id: Some(org_id),
            allowed_domains: Some(allowed_domains),
            invite: Some(invite),
            supports_confirmation: Some(supports_confirmation),
            creation_date: Some("2024-01-01T00:00:00Z".to_string()),
        }
    }

    /// Builds an invite + its secret and the organization public key it binds, all consistent with
    /// the client's org key.
    fn build_invite(
        client: &InviteLinkClient,
        org_id: OrganizationId,
    ) -> (InviteSecret, Invite, B64) {
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
        let (secret, invite) = Invite::make_for_private_key(org_key, &wrapped, &mut ctx).unwrap();
        (secret, invite, org_public_key)
    }

    /// Regenerates the invite-link fixtures used by the WASM integration tests in
    /// `crates/bitwarden-wasm-internal/integration-tests/tests/org-fixtures.ts`. All five values
    /// belong together — the invites bind the thumbprint of the public key of the private key they
    /// wrap — so they must always be copied over as a set.
    #[tokio::test]
    #[ignore = "Manual test to generate integration-test fixtures"]
    async fn generate_integration_test_fixtures() {
        let org_id: OrganizationId = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap();
        let core = Client::init_test_account(
            bitwarden_core::client::test_accounts::test_bitwarden_com_account(),
        )
        .await;
        let client = core.invite_link();

        let mut ctx = client.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(org_id);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = B64::from(
            ctx.get_public_key(private_key)
                .unwrap()
                .to_der()
                .unwrap()
                .as_ref(),
        );
        let wrapped = ctx.wrap_private_key(org_key, private_key).unwrap();
        let (secret, invite) = Invite::make_for_private_key(org_key, &wrapped, &mut ctx).unwrap();

        // The same invite with the organization-key envelope stripped, which drives the acceptance
        // (rather than self-confirmation) branch. It shares the invite secret and the bound
        // public-key thumbprint, so one secret and one public key serve both invites.
        let mut no_confirmation = invite.clone();
        no_confirmation.disable_confirmation();
        assert!(invite.supports_confirmation() && !no_confirmation.supports_confirmation());

        println!("TEST_ORG_WRAPPED_PRIVATE_KEY = {}", wrapped.to_string());
        println!("TEST_ORG_PUBLIC_KEY = {public_key}");
        println!("TEST_INVITE = {}", String::from(&invite));
        println!(
            "TEST_INVITE_NO_CONFIRMATION = {}",
            String::from(&no_confirmation)
        );
        println!("TEST_INVITE_SECRET = {}", String::from(&secret));
    }

    #[tokio::test]
    async fn create_invite_link_posts_and_returns_link_without_confirmation() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(OrganizationPrivateKeyResponseModel {
                            object: None,
                            private_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|org, model| {
                        let model = model.unwrap();
                        Ok(echo_link_response(
                            org,
                            model.allowed_domains,
                            model.invite,
                            model.supports_confirmation,
                        ))
                    })
                    .once();
            }),
        );
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let link = client
            .create_invite_link(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();

        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
        assert!(!String::from(&link.invite).is_empty());
        assert!(!link.invite.supports_confirmation());
    }

    #[tokio::test]
    async fn create_invite_link_posts_and_returns_link_with_confirmation() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(OrganizationPrivateKeyResponseModel {
                            object: None,
                            private_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|org, model| {
                        let model = model.unwrap();
                        Ok(echo_link_response(
                            org,
                            model.allowed_domains,
                            model.invite,
                            model.supports_confirmation,
                        ))
                    })
                    .once();
            }),
        );
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let link = client
            .create_invite_link(org_id, vec!["example.com".to_string()], true)
            .await
            .unwrap();

        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
        assert!(!String::from(&link.invite).is_empty());
        assert!(link.invite.supports_confirmation());
    }

    #[tokio::test]
    async fn create_invite_link_two_calls_produce_different_invites() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(OrganizationPrivateKeyResponseModel {
                            object: None,
                            private_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .times(2);
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|org, model| {
                        let model = model.unwrap();
                        Ok(echo_link_response(
                            org,
                            model.allowed_domains,
                            model.invite,
                            model.supports_confirmation,
                        ))
                    })
                    .times(2);
            }),
        );
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let link1 = client
            .create_invite_link(org_id, vec![], false)
            .await
            .unwrap();
        let link2 = client
            .create_invite_link(org_id, vec![], false)
            .await
            .unwrap();

        assert_ne!(String::from(&link1.invite), String::from(&link2.invite));
    }

    #[tokio::test]
    async fn create_invite_link_with_unknown_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(OrganizationPrivateKeyResponseModel {
                            object: None,
                            private_key: for_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
            }),
        );
        // The wrapped key is bound to the client's own org key; unwrapping it under a different
        // organization's key slot (which is absent from the store) must fail.
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let result = client.create_invite_link(other_org_id, vec![], false).await;

        assert!(matches!(result, Err(InviteLinkError::Invite(_))));
    }

    #[tokio::test]
    async fn create_invite_link_surfaces_api_errors() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(|_org| Err(std::io::Error::other("boom").into()));
            }),
        );

        let result = client.create_invite_link(org_id, vec![], false).await;

        assert!(matches!(result, Err(InviteLinkError::Api(_))));
    }

    #[tokio::test]
    async fn get_invite_secret_round_trips_to_the_invite_secret() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id, ApiClient::new_mocked(|_| {}));

        // A valid invite for the org must yield a non-empty secret recovered via the org key.
        let (_secret, invite, _org_public_key) = build_invite(&client, org_id);
        let secret = client.get_invite_secret(org_id, invite).unwrap();
        assert!(!String::from(&secret).is_empty());
    }

    #[tokio::test]
    async fn accept_and_confirm_succeeds_for_confirmable_invite() {
        let org_id = OrganizationId::new_v4();
        // `get_public_key` returns the base64 key held in this cell, and `get_invite` returns the
        // serialized invite; both are filled after the invite is generated below.
        let recovery = Arc::new(std::sync::Mutex::new(None::<String>));
        let invite_cell = Arc::new(std::sync::Mutex::new(None::<String>));
        let recovery_mock = recovery.clone();
        let invite_mock = invite_cell.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_public_key()
                    .returning(move |_id| {
                        Ok(OrganizationPublicKeyResponseModel {
                            object: None,
                            public_key: recovery_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_get_invite()
                    .returning(move |_model| {
                        Ok(OrganizationInviteResponseModel {
                            invite: invite_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_confirm_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        let (secret, invite, org_public_key) = build_invite(&client, org_id);
        assert!(invite.supports_confirmation());
        // The recovery public key returned by the "server" matches the invite's bound org key.
        *recovery.lock().unwrap() = Some(String::from(&org_public_key));
        *invite_cell.lock().unwrap() = Some(String::from(&invite));

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
        // Without enrollment the recovery key is never fetched, so only `get_invite` and
        // `confirm_invite_link` run.
        let invite_cell = Arc::new(std::sync::Mutex::new(None::<String>));
        let invite_mock = invite_cell.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organization_users_api
                    .expect_get_invite()
                    .returning(move |_model| {
                        Ok(OrganizationInviteResponseModel {
                            invite: invite_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_confirm_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        let (secret, invite, _org_public_key) = build_invite(&client, org_id);
        *invite_cell.lock().unwrap() = Some(String::from(&invite));
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
        let invite_cell = Arc::new(std::sync::Mutex::new(None::<String>));
        let invite_mock = invite_cell.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organization_users_api
                    .expect_get_invite()
                    .returning(move |_model| {
                        Ok(OrganizationInviteResponseModel {
                            invite: invite_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_accept_invite_link()
                    .returning(|_model| Ok(()))
                    .once();
            }),
        );

        // An invite with confirmation disabled routes to the acceptance branch.
        let (secret, mut invite, _org_public_key) = build_invite(&client, org_id);
        invite.disable_confirmation();
        assert!(!invite.supports_confirmation());
        *invite_cell.lock().unwrap() = Some(String::from(&invite));

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
        let invite_cell = Arc::new(std::sync::Mutex::new(None::<String>));
        let recovery_mock = recovery.clone();
        let invite_mock = invite_cell.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_public_key()
                    .returning(move |_id| {
                        Ok(OrganizationPublicKeyResponseModel {
                            object: None,
                            public_key: recovery_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
                mock.organization_users_api
                    .expect_get_invite()
                    .returning(move |_model| {
                        Ok(OrganizationInviteResponseModel {
                            invite: invite_mock.lock().unwrap().clone(),
                        })
                    })
                    .once();
            }),
        );

        let (secret, invite, _org_public_key) = build_invite(&client, org_id);
        *invite_cell.lock().unwrap() = Some(String::from(&invite));
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
