use std::sync::Arc;

use bitwarden_api_api::models::{
    CreateOrganizationInviteLinkRequestModel, RefreshOrganizationInviteLinkRequestModel,
    UpdateOrganizationInviteLinkRequestModel,
};
use bitwarden_core::{
    ApiError, FromClient, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{EncString, KeyStore};
use bitwarden_organization_crypto::invite::{Invite, InviteSecret};
use http::StatusCode;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{InviteLinkError, OrganizationInviteLink, OrganizationInviteLinkView};

/// Client for organization invite link administrative (organization-key) operations: creating,
/// refreshing, updating, deleting, and inspecting invite links, and recovering the invite secret.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct InviteLinkAdminClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

// The `create`/`refresh` methods delegate to the deprecated `create_invite_link`/
// `refresh_invite_link`, and the `wasm_bindgen`-generated shims for those deprecated exports call
// them; both would otherwise emit deprecation warnings from code we cannot annotate individually.
#[allow(deprecated)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl InviteLinkAdminClient {
    /// Get an existing invite link.
    pub async fn get(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Option<OrganizationInviteLinkView>, InviteLinkError> {
        let response = match self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .get(organization_id.into())
            .await
        {
            Ok(response) => response,
            Err(ApiError::Response(rc)) if rc.status == StatusCode::NOT_FOUND => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let mut ctx = self.key_store.context();
        OrganizationInviteLink::try_from(response)
            .and_then(|link| link.to_view(&mut ctx))
            .map(Some)
    }

    /// Delete an existing invite link.
    pub async fn delete(&self, organization_id: OrganizationId) -> Result<(), InviteLinkError> {
        self.api_configurations
            .api_client
            .organization_invite_links_api()
            .delete(organization_id.into())
            .await?;
        Ok(())
    }

    /// Creates a new organization invite and posts it to the server, returning the full
    /// [`OrganizationInviteLink`] persisted by the server.
    ///
    /// # Security
    /// Only the sealed invite is posted to the server; the invite secret is never sent. Use
    /// [`InviteLinkAdminClient::get_invite_secret`] to recover the secret needed to reconstruct the
    /// invite link.
    #[deprecated(note = "Use `create`, which returns an `OrganizationInviteLinkView`, instead")]
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
    #[deprecated(
        note = "Use `create` or `refresh`, which returns an `OrganizationInviteLinkView`, instead"
    )]
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

    /// Creates a new organization invite link.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLinkView, InviteLinkError> {
        if allowed_domains.is_empty() {
            return Err(InviteLinkError::NoAllowedDomains);
        }

        let link = self
            .create_invite_link(organization_id, allowed_domains, supports_confirmation)
            .await?;

        let mut ctx = self.key_store.context();
        link.to_view(&mut ctx)
    }

    /// Refreshes an existing invite link.
    pub async fn refresh(
        &self,
        organization_id: OrganizationId,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLinkView, InviteLinkError> {
        let link = self
            .refresh_invite_link(organization_id, supports_confirmation)
            .await?;

        let mut ctx = self.key_store.context();
        link.to_view(&mut ctx)
    }

    /// Updates the allowed domains for an existing organization invite link.
    pub async fn update_allowed_domains(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
    ) -> Result<OrganizationInviteLinkView, InviteLinkError> {
        if allowed_domains.is_empty() {
            return Err(InviteLinkError::NoAllowedDomains);
        }

        let response = self
            .api_configurations
            .api_client
            .organization_invite_links_api()
            .update(
                organization_id.into(),
                Some(UpdateOrganizationInviteLinkRequestModel { allowed_domains }),
            )
            .await?;

        let mut ctx = self.key_store.context();
        OrganizationInviteLink::try_from(response)?.to_view(&mut ctx)
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

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::OrganizationInviteLinkResponseModel};
    use bitwarden_core::{
        Client, client::ApiConfigurations, key_management::create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{
        PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    };
    use bitwarden_encoding::B64;

    use super::*;
    use crate::InviteLinkClientExt as _;

    fn make_client(org_id: OrganizationId, api_client: ApiClient) -> InviteLinkAdminClient {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_and_org_key(user_key, org_id, org_key);
        InviteLinkAdminClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    /// Wraps a fresh private key under the client's organization key and returns the serialized
    /// [`EncString`], matching what the server's `get_private_key` endpoint would return.
    fn wrapped_org_private_key(client: &InviteLinkAdminClient, org_id: OrganizationId) -> String {
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
        let client = core.invite_link().admin();

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
    async fn create_posts_and_returns_link_without_confirmation() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(
                            bitwarden_api_api::models::OrganizationPrivateKeyResponseModel {
                                object: None,
                                private_key: for_mock.lock().unwrap().clone(),
                            },
                        )
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
            .create(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();

        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
        assert!(!link.supports_confirmation);
    }

    #[tokio::test]
    async fn create_posts_and_returns_link_with_confirmation() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(
                            bitwarden_api_api::models::OrganizationPrivateKeyResponseModel {
                                object: None,
                                private_key: for_mock.lock().unwrap().clone(),
                            },
                        )
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
            .create(org_id, vec!["example.com".to_string()], true)
            .await
            .unwrap();

        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
        assert!(link.supports_confirmation);
    }

    #[tokio::test]
    async fn create_builds_url_fragment_from_org_code_and_secret() {
        let org_id = OrganizationId::new_v4();
        let code = uuid::Uuid::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(
                            bitwarden_api_api::models::OrganizationPrivateKeyResponseModel {
                                object: None,
                                private_key: for_mock.lock().unwrap().clone(),
                            },
                        )
                    })
                    .once();
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(move |org, model| {
                        let model = model.unwrap();
                        // Pin the code so the fragment's middle segment is deterministic.
                        let mut response = echo_link_response(
                            org,
                            model.allowed_domains,
                            model.invite,
                            model.supports_confirmation,
                        );
                        response.code = Some(code);
                        Ok(response)
                    })
                    .once();
            }),
        );
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let link = client
            .create(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();

        // Fragment shape: /join/{org}/{code}?key={secret}. The org id and server-issued code are
        // deterministic; the trailing secret must be a real, parseable `InviteSecret`.
        let prefix = format!("/join/{org_id}/{code}?key=");
        let key = link
            .url_fragment
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("unexpected fragment: {}", link.url_fragment));
        assert!(key.parse::<InviteSecret>().is_ok());
    }

    #[tokio::test]
    async fn create_two_calls_produce_different_invites() {
        let org_id = OrganizationId::new_v4();
        let wrapped = Arc::new(std::sync::Mutex::new(None::<String>));
        let for_mock = wrapped.clone();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(move |mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(move |_org| {
                        Ok(
                            bitwarden_api_api::models::OrganizationPrivateKeyResponseModel {
                                object: None,
                                private_key: for_mock.lock().unwrap().clone(),
                            },
                        )
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
            .create(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();
        let link2 = client
            .create(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();

        assert_ne!(&link1.url_fragment, &link2.url_fragment);
    }

    #[tokio::test]
    async fn create_with_unknown_organization_id_fails() {
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
                        Ok(
                            bitwarden_api_api::models::OrganizationPrivateKeyResponseModel {
                                object: None,
                                private_key: for_mock.lock().unwrap().clone(),
                            },
                        )
                    })
                    .once();
            }),
        );
        // The wrapped key is bound to the client's own org key; unwrapping it under a different
        // organization's key slot (which is absent from the store) must fail.
        *wrapped.lock().unwrap() = Some(wrapped_org_private_key(&client, org_id));

        let result = client
            .create(other_org_id, vec![String::from("example.com")], false)
            .await;

        assert!(matches!(result, Err(InviteLinkError::Invite(_))));
    }

    #[tokio::test]
    async fn create_surfaces_api_errors() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organizations_api
                    .expect_get_private_key()
                    .returning(|_org| Err(std::io::Error::other("boom").into()));
            }),
        );

        let result = client
            .create(org_id, vec![String::from("example.com")], false)
            .await;

        assert!(matches!(result, Err(InviteLinkError::Api(_))));
    }
}
