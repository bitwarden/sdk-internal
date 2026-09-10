use std::sync::Arc;

use bitwarden_core::{
    Client, FromClient, OrganizationId, client::ApiConfigurations, key_management::KeySlotIds,
};
use bitwarden_crypto::KeyStore;
use bitwarden_organization_crypto::invite::{Invite, InviteSecret};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{InviteLinkAdminClient, InviteLinkError, InviteLinkUserClient, OrganizationInviteLink};

/// Client for organization invite link operations.
///
/// This is a thin entry point that exposes two focused sub-clients: [`InviteLinkAdminClient`] (via
/// [`admin`](Self::admin)) for administrator CRUD operations, and [`InviteLinkUserClient`] (via
/// [`user`](Self::user)) for invitee flows. The other methods on this type are deprecated redirects
/// kept for backwards compatibility.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct InviteLinkClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

impl InviteLinkClient {
    fn admin_client(&self) -> InviteLinkAdminClient {
        InviteLinkAdminClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }

    fn user_client(&self) -> InviteLinkUserClient {
        InviteLinkUserClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }
}

// The deprecated redirects below call methods on the sub-clients (some of which are themselves
// deprecated), and the `wasm_bindgen`-generated shims call the redirects; both would otherwise emit
// deprecation warnings from generated code we cannot annotate individually.
#[allow(deprecated)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl InviteLinkClient {
    /// Administrative (organization-key) invite link operations.
    pub fn admin(&self) -> InviteLinkAdminClient {
        self.admin_client()
    }

    /// Invitee (user) invite link operations.
    pub fn user(&self) -> InviteLinkUserClient {
        self.user_client()
    }

    /// Creates a new organization invite and posts it to the server.
    #[deprecated(note = "Use `invite_link().admin().create(...)` instead")]
    pub async fn create_invite_link(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        self.admin_client()
            .create_invite_link(organization_id, allowed_domains, supports_confirmation)
            .await
    }

    /// Refresh an existing invite link.
    /// This generates a new code and secret.
    #[deprecated(note = "Use `invite_link().admin().refresh(...)` instead")]
    pub async fn refresh_invite_link(
        &self,
        organization_id: OrganizationId,
        supports_confirmation: bool,
    ) -> Result<OrganizationInviteLink, InviteLinkError> {
        self.admin_client()
            .refresh_invite_link(organization_id, supports_confirmation)
            .await
    }

    /// Using the organization key, recovers the [`InviteSecret`] from the invite carried in the
    /// given [`OrganizationInviteLink`] so an admin can reconstruct the invite link.
    #[deprecated(
        note = "Use `invite_link().admin().create(...)` or `invite_link().admin().refresh(...)`, which return an `OrganizationInviteLinkView`, instead"
    )]
    #[cfg_attr(feature = "wasm", wasm_bindgen(unchecked_return_type = "InviteSecret"))]
    pub fn get_invite_secret(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
    ) -> Result<InviteSecret, InviteLinkError> {
        self.admin_client()
            .get_invite_secret(organization_id, invite)
    }

    /// Accepts an organization invite for the current user, optionally enrolling into account
    /// recovery (when `enroll_into_account_recovery` is set) and — when the invite supports
    /// confirmation — self-confirming.
    #[deprecated(note = "Use `invite_link().user().accept_and_optionally_confirm(...)` instead")]
    pub async fn accept_and_optionally_confirm(
        &self,
        organization_id: OrganizationId,
        code: String,
        invite_secret: InviteSecret,
        default_collection_name: String,
        enroll_into_account_recovery: bool,
    ) -> Result<(), InviteLinkError> {
        self.user_client()
            .accept_and_optionally_confirm(
                organization_id,
                code,
                invite_secret,
                default_collection_name,
                enroll_into_account_recovery,
            )
            .await
    }
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
#[allow(deprecated)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{OrganizationInviteLinkResponseModel, OrganizationPrivateKeyResponseModel},
    };
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;

    fn make_client(org_id: OrganizationId, api_client: ApiClient) -> InviteLinkClient {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_and_org_key(user_key, org_id, org_key);
        InviteLinkClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    /// The deprecated `create_invite_link` redirect on the parent client must still route through
    /// to the admin sub-client and post a link, preserving backwards compatibility.
    #[tokio::test]
    async fn create_invite_link_redirects_to_admin_client() {
        use bitwarden_core::key_management::SymmetricKeySlotId;
        use bitwarden_crypto::PublicKeyEncryptionAlgorithm;

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
                        Ok(OrganizationInviteLinkResponseModel {
                            object: None,
                            id: Some(uuid::Uuid::new_v4()),
                            code: Some(uuid::Uuid::new_v4()),
                            organization_id: Some(org),
                            allowed_domains: Some(model.allowed_domains),
                            invite: Some(model.invite),
                            supports_confirmation: Some(model.supports_confirmation),
                            creation_date: Some("2024-01-01T00:00:00Z".to_string()),
                        })
                    })
                    .once();
            }),
        );

        // Wrap a private key under the client's org key, mirroring the server's `get_private_key`.
        let wrapped_key = {
            let mut ctx = client.key_store.context();
            let org_key = SymmetricKeySlotId::Organization(org_id);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.wrap_private_key(org_key, private_key)
                .unwrap()
                .to_string()
        };
        *wrapped.lock().unwrap() = Some(wrapped_key);

        let link = client
            .create_invite_link(org_id, vec!["example.com".to_string()], false)
            .await
            .unwrap();

        assert_eq!(link.allowed_domains, vec!["example.com".to_string()]);
        assert!(!link.supports_confirmation);
    }
}
