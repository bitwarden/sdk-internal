//! Loads provider and organization keys from state into the key store.
//!
//! Provider keys are encapsulated to the user's public key. Organization keys are either
//! encapsulated to the user's public key, or wrapped by a provider key for organizations the user
//! accesses through a provider. Both are read from their repositories and unwrapped into the
//! [`SymmetricKeySlotId::Provider`] and [`SymmetricKeySlotId::Organization`] slots.

use std::collections::HashMap;

use bitwarden_crypto::{CryptoError, KeyStoreContext};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_state::{registry::StateRegistryError, repository::RepositoryError};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    Client, OrganizationId, ProviderId,
    client::persisted_state::{OrganizationKeyEnvelope, OrganizationSharedKey, ProviderSharedKey},
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
};

/// Which provider and organization keys are loaded into the key store.
///
/// Contains only identifiers, never key material.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct OrganizationKeysStatus {
    /// Organizations whose key is loaded.
    pub organizations: Vec<OrganizationId>,
    /// Organizations present in state whose key could not be loaded.
    pub failed_organizations: Vec<OrganizationId>,
    /// Providers whose key is loaded.
    pub providers: Vec<ProviderId>,
    /// Providers present in state whose key could not be loaded.
    pub failed_providers: Vec<ProviderId>,
}

/// The decrypted keys of the organizations whose keys are loaded.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[bitwarden_ffi::wasm_record]
pub struct OrganizationKeysResponse {
    /// The decrypted organization keys, by organization.
    pub keys: HashMap<OrganizationId, B64>,
}

/// The decrypted keys of the providers whose keys are loaded.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[bitwarden_ffi::wasm_record]
pub struct ProviderKeysResponse {
    /// The decrypted provider keys, by provider.
    pub keys: HashMap<ProviderId, B64>,
}

/// Errors returned when organization keys cannot be loaded or inspected.
///
/// A key that fails to unwrap is not an error: it is reported in [`OrganizationKeysStatus`].
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum OrganizationKeysError {
    /// The SDK is locked.
    #[error("The SDK must be unlocked to load organization keys")]
    NotUnlocked,
    /// A repository could not be accessed.
    #[error(transparent)]
    StateRegistry(#[from] StateRegistryError),
    /// A repository could not be read.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Re-derives all provider and organization keys from state.
///
/// Replaces every [`SymmetricKeySlotId::Provider`] and [`SymmetricKeySlotId::Organization`] slot,
/// so keys of providers and organizations the user has left are dropped. A key that fails to
/// unwrap is logged and reported as failed, and does not affect the others.
pub(crate) async fn load_organization_keys(
    client: &Client,
) -> Result<OrganizationKeysStatus, OrganizationKeysError> {
    ensure_unlocked(client)?;
    let (providers, organizations) = read_organization_keys(client).await?;

    let mut ctx = client.internal.get_key_store().context_mut();
    Ok(set_organization_keys(&providers, &organizations, &mut ctx))
}

/// Reports which provider and organization keys in state are loaded into the key store, without
/// loading anything.
pub(crate) async fn get_organization_keys_status(
    client: &Client,
) -> Result<OrganizationKeysStatus, OrganizationKeysError> {
    ensure_unlocked(client)?;
    let (providers, organizations) = read_organization_keys(client).await?;

    let key_store = client.internal.get_key_store();
    let ctx = key_store.context();
    let (loaded_providers, failed_providers) = providers
        .iter()
        .map(|p| p.provider_id)
        .partition(|id| ctx.has_symmetric_key(SymmetricKeySlotId::Provider(*id)));
    let (loaded_organizations, failed_organizations) = organizations
        .iter()
        .map(|o| o.org_id)
        .partition(|id| ctx.has_symmetric_key(SymmetricKeySlotId::Organization(*id)));

    Ok(OrganizationKeysStatus {
        organizations: loaded_organizations,
        failed_organizations,
        providers: loaded_providers,
        failed_providers,
    })
}

/// Exports the loaded organization keys. See `CryptoClient::dangerous_get_organization_keys`.
pub(crate) async fn dangerous_get_organization_keys(
    client: &Client,
) -> Result<OrganizationKeysResponse, OrganizationKeysError> {
    let status = get_organization_keys_status(client).await?;
    let keys = dangerous_get_keys(
        client,
        status.organizations,
        SymmetricKeySlotId::Organization,
    );
    Ok(OrganizationKeysResponse { keys })
}

/// Exports the loaded provider keys. See `CryptoClient::dangerous_get_provider_keys`.
pub(crate) async fn dangerous_get_provider_keys(
    client: &Client,
) -> Result<ProviderKeysResponse, OrganizationKeysError> {
    let status = get_organization_keys_status(client).await?;
    let keys = dangerous_get_keys(client, status.providers, SymmetricKeySlotId::Provider);
    Ok(ProviderKeysResponse { keys })
}

fn dangerous_get_keys<Id: Copy + Eq + std::hash::Hash>(
    client: &Client,
    ids: Vec<Id>,
    slot: fn(Id) -> SymmetricKeySlotId,
) -> HashMap<Id, B64> {
    let key_store = client.internal.get_key_store();
    let ctx = key_store.context();
    ids.into_iter()
        .filter_map(|id| {
            // Exporting these keys is the purpose of the deprecated bridge this serves. There
            // should be no other reason to do this. Do not use this as an example.
            #[expect(deprecated)]
            let key = ctx.dangerous_get_symmetric_key(slot(id)).ok()?;
            Some((id, key.to_base64()))
        })
        .collect()
}

fn ensure_unlocked(client: &Client) -> Result<(), OrganizationKeysError> {
    if client
        .internal
        .get_key_store()
        .context()
        .has_symmetric_key(SymmetricKeySlotId::User)
    {
        Ok(())
    } else {
        Err(OrganizationKeysError::NotUnlocked)
    }
}

/// Reads all persisted provider and organization keys.
pub(crate) async fn read_organization_keys(
    client: &Client,
) -> Result<(Vec<ProviderSharedKey>, Vec<OrganizationSharedKey>), OrganizationKeysError> {
    let state = client.platform().state();
    let providers = state.get::<ProviderSharedKey>()?.list().await?;
    let organizations = state.get::<OrganizationSharedKey>()?.list().await?;
    Ok((providers, organizations))
}

/// Replaces all provider and organization keys in the key store with the given ones.
///
/// Taking a single mutable context means other contexts never observe a partially applied set.
/// Providers are unwrapped first, since provider-wrapped organization keys depend on them.
pub(crate) fn set_organization_keys(
    providers: &[ProviderSharedKey],
    organizations: &[OrganizationSharedKey],
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> OrganizationKeysStatus {
    // Drop keys of providers and organizations the user is no longer a member of.
    ctx.retain_symmetric_keys(|key| {
        !matches!(
            key,
            SymmetricKeySlotId::Organization(_) | SymmetricKeySlotId::Provider(_)
        )
    });

    let mut status = OrganizationKeysStatus::default();

    if !ctx.has_private_key(PrivateKeySlotId::UserPrivateKey) {
        warn!("User private key is missing, cannot load organization keys");
        status.failed_providers = providers.iter().map(|p| p.provider_id).collect();
        status.failed_organizations = organizations.iter().map(|o| o.org_id).collect();
        return status;
    }

    for ProviderSharedKey { provider_id, key } in providers {
        let result = key
            .decapsulate(PrivateKeySlotId::UserPrivateKey, ctx)
            .and_then(|id| {
                ctx.persist_symmetric_key(id, SymmetricKeySlotId::Provider(*provider_id))
            });
        match result {
            Ok(()) => status.providers.push(*provider_id),
            Err(error) => {
                warn!(%provider_id, %error, "Failed to load provider key");
                status.failed_providers.push(*provider_id);
            }
        }
    }

    for OrganizationSharedKey { org_id, key } in organizations {
        let result = unwrap_organization_key(key, ctx).and_then(|id| {
            ctx.persist_symmetric_key(id, SymmetricKeySlotId::Organization(*org_id))
        });
        match result {
            Ok(()) => status.organizations.push(*org_id),
            Err(error) => {
                warn!(%org_id, %error, "Failed to load organization key");
                status.failed_organizations.push(*org_id);
            }
        }
    }

    info!(
        organizations = status.organizations.len(),
        failed_organizations = status.failed_organizations.len(),
        providers = status.providers.len(),
        failed_providers = status.failed_providers.len(),
        "Loaded organization keys"
    );

    status
}

/// Unwraps an organization key into a local key slot.
fn unwrap_organization_key(
    envelope: &OrganizationKeyEnvelope,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<SymmetricKeySlotId, CryptoError> {
    match envelope {
        OrganizationKeyEnvelope::Organization { key } => {
            key.decapsulate(PrivateKeySlotId::UserPrivateKey, ctx)
        }
        // Fails with a missing-key error if the provider key did not load.
        OrganizationKeyEnvelope::Provider { provider_id, key } => {
            ctx.unwrap_symmetric_key(SymmetricKeySlotId::Provider(*provider_id), key)
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        Decryptable, EncString, KeyStore, PrimitiveEncryptable, PublicKey,
        PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm, UnsignedSharedKey,
    };

    use super::*;

    const PROBE: &str = "probe";

    fn org_id(n: u128) -> OrganizationId {
        OrganizationId::new(uuid::Uuid::from_u128(n))
    }

    fn provider_id(n: u128) -> ProviderId {
        ProviderId::new(uuid::Uuid::from_u128(0x1000 + n))
    }

    /// A client unlocked with a fresh user key and private key. Returns the user's public key.
    fn unlocked_client() -> (Client, PublicKey) {
        let client = Client::new_test(None);
        let public_key = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .unwrap();
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.persist_private_key(private_key, PrivateKeySlotId::UserPrivateKey)
                .unwrap();
            ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)
                .unwrap()
        };
        (client, public_key)
    }

    /// The provider and organization keys as the server issues them, held in the same slots the
    /// client loads them into, so loaded keys can be checked against them.
    struct IssuedKeys {
        store: KeyStore<KeySlotIds>,
        public_key: PublicKey,
    }

    impl IssuedKeys {
        fn for_user(public_key: &PublicKey) -> Self {
            Self {
                store: KeyStore::default(),
                public_key: public_key.clone(),
            }
        }

        fn make(&self, slot: SymmetricKeySlotId) {
            let mut ctx = self.store.context_mut();
            let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(key, slot).unwrap();
        }

        fn provider(&self, provider_id: ProviderId) -> ProviderSharedKey {
            let slot = SymmetricKeySlotId::Provider(provider_id);
            self.make(slot);
            ProviderSharedKey {
                provider_id,
                key: UnsignedSharedKey::encapsulate(slot, &self.public_key, &self.store.context())
                    .unwrap(),
            }
        }

        fn organization(&self, org_id: OrganizationId) -> OrganizationSharedKey {
            let slot = SymmetricKeySlotId::Organization(org_id);
            self.make(slot);
            OrganizationSharedKey {
                org_id,
                key: OrganizationKeyEnvelope::Organization {
                    key: UnsignedSharedKey::encapsulate(
                        slot,
                        &self.public_key,
                        &self.store.context(),
                    )
                    .unwrap(),
                },
            }
        }

        /// An organization key wrapped by the key of an already issued provider.
        fn provider_organization(
            &self,
            org_id: OrganizationId,
            provider_id: ProviderId,
        ) -> OrganizationSharedKey {
            let slot = SymmetricKeySlotId::Organization(org_id);
            self.make(slot);
            OrganizationSharedKey {
                org_id,
                key: OrganizationKeyEnvelope::Provider {
                    provider_id,
                    key: self
                        .store
                        .context_mut()
                        .wrap_symmetric_key(SymmetricKeySlotId::Provider(provider_id), slot)
                        .unwrap(),
                },
            }
        }

        /// Asserts the client holds the issued key in `slot`.
        fn assert_loaded(&self, client: &Client, slot: SymmetricKeySlotId) {
            let probe: EncString = PROBE.encrypt(&mut self.store.context(), slot).unwrap();
            let decrypted: String = probe
                .decrypt(&mut client.internal.get_key_store().context(), slot)
                .unwrap();
            assert_eq!(decrypted, PROBE);
        }
    }

    async fn store_keys(
        client: &Client,
        providers: &[ProviderSharedKey],
        organizations: &[OrganizationSharedKey],
    ) {
        let state = client.platform().state();
        state
            .get::<ProviderSharedKey>()
            .unwrap()
            .replace_all(
                providers
                    .iter()
                    .map(|p| (p.provider_id, p.clone()))
                    .collect(),
            )
            .await
            .unwrap();
        state
            .get::<OrganizationSharedKey>()
            .unwrap()
            .replace_all(
                organizations
                    .iter()
                    .map(|o| (o.org_id, o.clone()))
                    .collect(),
            )
            .await
            .unwrap();
    }

    fn has_key(client: &Client, slot: SymmetricKeySlotId) -> bool {
        client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(slot)
    }

    /// Puts an unrelated key into `slot`, as if loaded earlier.
    fn set_stale_key(client: &Client, slot: SymmetricKeySlotId) {
        let mut ctx = client.internal.get_key_store().context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        ctx.persist_symmetric_key(key, slot).unwrap();
    }

    #[tokio::test]
    async fn test_load_organization_keys_user_encapsulated() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let org = issued.organization(org_id(1));
        store_keys(&client, &[], &[org]).await;

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(
            status,
            OrganizationKeysStatus {
                organizations: vec![org_id(1)],
                ..Default::default()
            }
        );
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(1)));
    }

    #[tokio::test]
    async fn test_load_organization_keys_provider_wrapped() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let provider = issued.provider(provider_id(1));
        let org = issued.provider_organization(org_id(1), provider_id(1));
        store_keys(&client, &[provider], &[org]).await;

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(
            status,
            OrganizationKeysStatus {
                organizations: vec![org_id(1)],
                providers: vec![provider_id(1)],
                ..Default::default()
            }
        );
        issued.assert_loaded(&client, SymmetricKeySlotId::Provider(provider_id(1)));
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(1)));
    }

    #[tokio::test]
    async fn test_load_organization_keys_mixed() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let provider = issued.provider(provider_id(1));
        let direct = issued.organization(org_id(1));
        let through_provider = issued.provider_organization(org_id(2), provider_id(1));
        store_keys(&client, &[provider], &[direct, through_provider]).await;

        let mut status = load_organization_keys(&client).await.unwrap();
        status.organizations.sort();

        assert_eq!(status.organizations, vec![org_id(1), org_id(2)]);
        assert_eq!(status.providers, vec![provider_id(1)]);
        assert!(status.failed_organizations.is_empty());
        assert!(status.failed_providers.is_empty());
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(1)));
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(2)));
    }

    #[tokio::test]
    async fn test_load_organization_keys_missing_provider_fails_only_its_organizations() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        // Issued, but not in state.
        issued.provider(provider_id(1));
        let through_provider = issued.provider_organization(org_id(1), provider_id(1));
        let direct = issued.organization(org_id(2));
        store_keys(&client, &[], &[through_provider, direct]).await;

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(status.organizations, vec![org_id(2)]);
        assert_eq!(status.failed_organizations, vec![org_id(1)]);
        assert!(!has_key(
            &client,
            SymmetricKeySlotId::Organization(org_id(1))
        ));
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(2)));
    }

    #[tokio::test]
    async fn test_load_organization_keys_empty_state_clears_stale_keys() {
        let (client, _) = unlocked_client();
        set_stale_key(&client, SymmetricKeySlotId::Organization(org_id(1)));
        set_stale_key(&client, SymmetricKeySlotId::Provider(provider_id(1)));

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(status, OrganizationKeysStatus::default());
        assert!(!has_key(
            &client,
            SymmetricKeySlotId::Organization(org_id(1))
        ));
        assert!(!has_key(
            &client,
            SymmetricKeySlotId::Provider(provider_id(1))
        ));
        assert!(has_key(&client, SymmetricKeySlotId::User));
    }

    #[tokio::test]
    async fn test_load_organization_keys_drops_keys_no_longer_in_state() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let kept = issued.organization(org_id(1));
        let left = issued.organization(org_id(2));
        store_keys(&client, &[], &[kept.clone(), left]).await;
        load_organization_keys(&client).await.unwrap();

        store_keys(&client, &[], &[kept]).await;
        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(status.organizations, vec![org_id(1)]);
        assert!(!has_key(
            &client,
            SymmetricKeySlotId::Organization(org_id(2))
        ));
    }

    #[tokio::test]
    async fn test_load_organization_keys_missing_private_key_fails_all() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let provider = issued.provider(provider_id(1));
        let org = issued.organization(org_id(1));
        store_keys(&client, &[provider], &[org]).await;
        set_stale_key(&client, SymmetricKeySlotId::Organization(org_id(1)));
        client
            .internal
            .get_key_store()
            .context_mut()
            .drop_private_key(PrivateKeySlotId::UserPrivateKey)
            .unwrap();

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(
            status,
            OrganizationKeysStatus {
                failed_organizations: vec![org_id(1)],
                failed_providers: vec![provider_id(1)],
                ..Default::default()
            }
        );
        assert!(!has_key(
            &client,
            SymmetricKeySlotId::Organization(org_id(1))
        ));
    }

    #[tokio::test]
    async fn test_load_organization_keys_corrupt_entry_is_isolated() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let (_, other_public_key) = unlocked_client();
        let foreign = IssuedKeys::for_user(&other_public_key);
        let good = issued.organization(org_id(1));
        // Encapsulated to another user's public key.
        let bad = foreign.organization(org_id(2));
        let bad_provider = foreign.provider(provider_id(1));
        store_keys(&client, &[bad_provider], &[good, bad]).await;

        let status = load_organization_keys(&client).await.unwrap();

        assert_eq!(status.organizations, vec![org_id(1)]);
        assert_eq!(status.failed_organizations, vec![org_id(2)]);
        assert_eq!(status.failed_providers, vec![provider_id(1)]);
        issued.assert_loaded(&client, SymmetricKeySlotId::Organization(org_id(1)));
    }

    #[tokio::test]
    async fn test_load_organization_keys_locked() {
        let client = Client::new_test(None);

        let result = load_organization_keys(&client).await;

        assert!(matches!(result, Err(OrganizationKeysError::NotUnlocked)));
    }

    #[tokio::test]
    async fn test_organization_keys_status_reports_without_loading() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let provider = issued.provider(provider_id(1));
        let org = issued.organization(org_id(1));
        store_keys(&client, &[provider], &[org]).await;

        let before = get_organization_keys_status(&client).await.unwrap();
        let loaded = load_organization_keys(&client).await.unwrap();
        let after = get_organization_keys_status(&client).await.unwrap();

        assert_eq!(
            before,
            OrganizationKeysStatus {
                failed_organizations: vec![org_id(1)],
                failed_providers: vec![provider_id(1)],
                ..Default::default()
            }
        );
        assert_eq!(after, loaded);
    }

    #[tokio::test]
    async fn test_dangerous_get_keys_returns_loaded_keys() {
        let (client, public_key) = unlocked_client();
        let issued = IssuedKeys::for_user(&public_key);
        let provider = issued.provider(provider_id(1));
        let org = issued.provider_organization(org_id(1), provider_id(1));
        store_keys(&client, &[provider], &[org]).await;
        load_organization_keys(&client).await.unwrap();

        let organizations = dangerous_get_organization_keys(&client).await.unwrap();
        let providers = dangerous_get_provider_keys(&client).await.unwrap();

        #[allow(deprecated)]
        let expected = |slot| {
            issued
                .store
                .context()
                .dangerous_get_symmetric_key(slot)
                .unwrap()
                .to_base64()
        };
        assert_eq!(
            organizations.keys,
            HashMap::from([(
                org_id(1),
                expected(SymmetricKeySlotId::Organization(org_id(1)))
            )])
        );
        assert_eq!(
            providers.keys,
            HashMap::from([(
                provider_id(1),
                expected(SymmetricKeySlotId::Provider(provider_id(1)))
            )])
        );
    }
}
