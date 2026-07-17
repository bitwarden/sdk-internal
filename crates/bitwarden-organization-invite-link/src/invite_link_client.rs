use std::sync::Arc;

use bitwarden_api_api::models::{
    AcceptOrganizationInviteLinkRequestModel, ConfirmOrganizationInviteLinkRequestModel,
    CreateOrganizationInviteLinkRequestModel,
};
use bitwarden_core::{
    ApiError, Client, FromClient, MissingFieldError, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CoseKeyThumbprintExt, CryptoError, EncString, KeyStore, PrimitiveEncryptable, PublicKey,
    PublicKeyEncryptionAlgorithm, SpkiPublicKeyBytes, UnsignedSharedKey,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::invite::{Invite, InviteKeyBundleError, InviteSecret};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

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
    /// Creates a new organization invite and posts it to the server, returning the
    /// [`InviteSecret`] carried in the invite link.
    ///
    /// # Security
    /// The returned [`InviteSecret`] MUST NOT be sent to the server; only the sealed invite is
    /// posted here.
    pub async fn make_invite(
        &self,
        organization_id: OrganizationId,
        allowed_domains: Vec<String>,
    ) -> Result<InviteSecret, InviteLinkError> {
        let wrapped_private_key = self.download_wrapped_private_key(organization_id).await?;

        // Confine the (non-Send) key store context to a synchronous scope so nothing is held
        // across the `.await` below.
        let (invite_secret, invite, supports_confirmation) = {
            let mut ctx = self.key_store.context();
            let org_key = SymmetricKeySlotId::Organization(organization_id);
            let (invite_secret, invite) =
                Invite::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)?;
            let supports_confirmation = invite.supports_confirmation();
            (invite_secret, String::from(&invite), supports_confirmation)
        };

        self.api_configurations
            .api_client
            .organization_invite_links_api()
            .create(
                organization_id.into(),
                Some(CreateOrganizationInviteLinkRequestModel {
                    allowed_domains,
                    invite,
                    supports_confirmation,
                }),
            )
            .await
            .map_err(ApiError::from)?;

        Ok(invite_secret)
    }

    /// Fetches the organization's invite from the server and, using the organization key, recovers
    /// the [`InviteSecret`] so an admin can reconstruct the invite link.
    pub async fn get_invite_secret(
        &self,
        organization_id: OrganizationId,
    ) -> Result<InviteSecret, InviteLinkError> {
        let invite = self.fetch_invite(organization_id).await?;

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
        let invite = self.fetch_invite(organization_id).await?;

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
                    code,
                    org_user_key,
                    reset_password_key,
                    default_user_collection_name,
                })
            } else {
                PendingPost::Accept(AcceptOrganizationInviteLinkRequestModel {
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
}

/// A prepared invite acceptance request, built while the key store context is held and posted once
/// it has been dropped.
enum PendingPost {
    Confirm(ConfirmOrganizationInviteLinkRequestModel),
    Accept(AcceptOrganizationInviteLinkRequestModel),
}

// Stubbed network helpers.
//
// The backend endpoints these represent do not exist yet, so they are stubbed and the real API
// wiring lands in a follow-up PR (see TODOs). They are kept as small private helpers so the public
// methods above do not change when the real calls are added. They are `async` because they stand
// in for network calls; the real implementations will `.await`, so silence `unused_async` until
// then.
#[allow(clippy::unused_async)]
impl InviteLinkClient {
    /// TODO(PM-40523): replace with a real API call that downloads the organization's private key,
    /// wrapped with the organization key. For now we derive one locally so the invite flow is
    /// exercisable end-to-end.
    async fn download_wrapped_private_key(
        &self,
        organization_id: OrganizationId,
    ) -> Result<EncString, InviteLinkError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        Ok(ctx.wrap_private_key(org_key, private_key)?)
    }

    /// TODO(PM-38749): replace with a real API call. The `get` invite-link endpoint currently
    /// returns no invite payload, so we synthesize a fresh invite from a locally-derived wrapped
    /// private key.
    async fn fetch_invite(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Invite, InviteLinkError> {
        // Test seam: let tests pin the invite the "server" returns so invitee flows can supply a
        // matching invite secret. Not compiled into release builds.
        #[cfg(test)]
        if let Some(invite) = TEST_INVITE.with(|slot| slot.borrow_mut().take()) {
            return Ok(invite);
        }

        let wrapped_private_key = self.download_wrapped_private_key(organization_id).await?;
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let (_invite_secret, invite) =
            Invite::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)?;
        Ok(invite)
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
thread_local! {
    /// Test-only injection point for [`InviteLinkClient::fetch_invite`]; see its `#[cfg(test)]`
    /// branch.
    static TEST_INVITE: std::cell::RefCell<Option<Invite>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::OrganizationPublicKeyResponseModel};
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

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

    /// Mocks the invite-links API so `create` succeeds.
    fn mocked_create_ok() -> ApiClient {
        ApiClient::new_mocked(|mock| {
            mock.organization_invite_links_api
                .expect_create()
                .returning(|_org, _model| Ok(()))
                .once();
        })
    }

    #[tokio::test]
    async fn make_invite_posts_and_returns_secret() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id, mocked_create_ok());

        let secret = client
            .make_invite(org_id, vec!["example.com".to_string()])
            .await
            .unwrap();

        assert!(!String::from(&secret).is_empty());
    }

    #[tokio::test]
    async fn make_invite_two_calls_produce_different_secrets() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(
            org_id,
            ApiClient::new_mocked(|mock| {
                mock.organization_invite_links_api
                    .expect_create()
                    .returning(|_org, _model| Ok(()))
                    .times(2);
            }),
        );

        let secret1 = client.make_invite(org_id, vec![]).await.unwrap();
        let secret2 = client.make_invite(org_id, vec![]).await.unwrap();

        assert_ne!(String::from(&secret1), String::from(&secret2));
    }

    #[tokio::test]
    async fn make_invite_with_unknown_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id, ApiClient::new_mocked(|_| {}));

        let result = client.make_invite(other_org_id, vec![]).await;

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

        let result = client.make_invite(org_id, vec![]).await;

        assert!(matches!(result, Err(InviteLinkError::Api(_))));
    }

    #[tokio::test]
    async fn get_invite_secret_round_trips_to_the_invite_secret() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id, ApiClient::new_mocked(|_| {}));

        // `fetch_invite` synthesizes a valid invite for the org; `get_invite_secret` must recover a
        // non-empty secret from it via the organization key.
        let secret = client.get_invite_secret(org_id).await.unwrap();
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
