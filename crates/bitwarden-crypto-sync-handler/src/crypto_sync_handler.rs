//! Key management work that runs on every sync.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;

#[cfg(any(feature = "uniffi", feature = "wasm"))]
use bitwarden_core::key_management::crypto::{ReinitUserCryptoError, ReinitUserCryptoRequest};
use bitwarden_core::{
    Client,
    client::persisted_state::{OrganizationSharedKey, ProviderSharedKey},
    key_management::{
        MasterPasswordUnlockData, OrganizationKeysError, V2UpgradeToken, WebAuthnPrfUnlockData,
        WebAuthnPrfUnlockOption, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
#[cfg(not(target_arch = "wasm32"))]
use bitwarden_core::{
    OrganizationId, ProviderId,
    client::persisted_state::OrganizationKeyEnvelope,
    key_management::{
        MasterPasswordError, V2UpgradeTokenError, WebAuthnPrfError,
        account_cryptographic_state::AccountKeysResponseParseError,
    },
};
use bitwarden_crypto::KeyId;
use bitwarden_state::repository::{RepositoryError, RepositoryItem};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// The parts of a sync response the key management sync handler needs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct CryptoSyncData {
    /// The account's user decryption options, as the server reports them on sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_decryption: Option<CryptoSyncUserDecryption>,
    /// The account's cryptographic state, as the server reports it on sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub account_cryptographic_state: Option<WrappedAccountCryptographicState>,
    /// The keys of the organizations the user is a member of, directly or through a provider.
    ///
    /// `None` leaves the persisted organization keys untouched. `Some` replaces them, so an empty
    /// list removes all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub organization_keys: Option<Vec<OrganizationSharedKey>>,
    /// The keys of the providers the user is a member of.
    ///
    /// `None` leaves the persisted provider keys untouched. `Some` replaces them, so an empty list
    /// removes all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub provider_keys: Option<Vec<ProviderSharedKey>>,
}

/// The user decryption options a sync response carries, narrowed to the parts key management owns.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct CryptoSyncUserDecryption {
    /// Unlock data for accounts that have a master password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub master_password_unlock: Option<MasterPasswordUnlockData>,
    /// Token allowing unlock after a V1 to V2 upgrade, when one is outstanding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub v2_upgrade_token: Option<V2UpgradeToken>,
    /// The WebAuthn PRF credentials the account can unlock with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub web_authn_prf_options: Option<Vec<WebAuthnPrfUnlockOption>>,
    /// The id of the account's current user key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_key_id: Option<KeyId>,
}

/// Errors returned when a sync response cannot be converted into [`CryptoSyncData`].
///
/// The conversion happens before anything is written to state, so returning one of these leaves
/// state untouched rather than partially updated.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
pub enum CryptoSyncDataParseError {
    /// The sync response carried master password unlock data that could not be parsed.
    #[error("Sync response carried unparseable master password unlock data")]
    MasterPasswordUnlock(#[source] MasterPasswordError),
    /// The sync response carried a V2 upgrade token that could not be parsed.
    #[error("Sync response carried an unparseable V2 upgrade token")]
    V2UpgradeToken(#[source] V2UpgradeTokenError),
    /// The sync response carried a WebAuthn PRF unlock option that could not be parsed.
    #[error("Sync response carried an unparseable WebAuthn PRF unlock option")]
    WebAuthnPrfOption(#[source] WebAuthnPrfError),
    /// The sync response carried a user key id that could not be parsed.
    #[error("Sync response carried an unparseable user key id")]
    UserKeyId(#[source] bitwarden_crypto::CryptoError),
    /// The sync response carried account cryptographic state that could not be parsed.
    #[error("Sync response carried unparseable account cryptographic state")]
    AccountCryptographicState(#[source] AccountKeysResponseParseError),
    /// The sync response carried an organization key that could not be parsed.
    #[error("Sync response carried an unparseable organization key")]
    OrganizationKey(#[source] bitwarden_crypto::CryptoError),
    /// The sync response carried a provider key that could not be parsed.
    #[error("Sync response carried an unparseable provider key")]
    ProviderKey(#[source] bitwarden_crypto::CryptoError),
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<&bitwarden_api_api::models::SyncResponseModel> for CryptoSyncData {
    type Error = CryptoSyncDataParseError;

    fn try_from(
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            user_decryption: response
                .user_decryption
                .as_deref()
                .map(CryptoSyncUserDecryption::try_from)
                .transpose()?,
            account_cryptographic_state: response
                .profile
                .as_deref()
                .and_then(|p| p.account_keys.as_deref())
                .map(WrappedAccountCryptographicState::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::AccountCryptographicState)?,
            organization_keys: response
                .profile
                .as_deref()
                .map(parse_organization_keys)
                .transpose()?,
            provider_keys: response
                .profile
                .as_deref()
                .map(parse_provider_keys)
                .transpose()?,
        })
    }
}

/// Parses the keys of the organizations the user is a member of, directly or through a provider.
///
/// Memberships without a key, e.g. an invited but unconfirmed member, are skipped. An
/// organization the user is a member of both directly and through a provider uses the provider
/// key, matching the clients.
#[cfg(not(target_arch = "wasm32"))]
fn parse_organization_keys(
    profile: &bitwarden_api_api::models::ProfileResponseModel,
) -> Result<Vec<OrganizationSharedKey>, CryptoSyncDataParseError> {
    let direct = profile.organizations.iter().flatten().filter_map(|org| {
        let (Some(id), Some(key)) = (org.id, org.key.as_deref()) else {
            return None;
        };
        Some(key.parse().map(|key| {
            (
                OrganizationId::new(id),
                OrganizationKeyEnvelope::Organization { key },
            )
        }))
    });

    let through_provider = profile
        .provider_organizations
        .iter()
        .flatten()
        .filter_map(|org| {
            let (Some(id), Some(key)) = (org.id, org.key.as_deref()) else {
                return None;
            };
            let Some(provider_id) = org.provider_id else {
                warn!(org_id = %id, "Skipping provider organization key without a provider id");
                return None;
            };
            Some(key.parse().map(|key| {
                (
                    OrganizationId::new(id),
                    OrganizationKeyEnvelope::Provider {
                        provider_id: ProviderId::new(provider_id),
                        key,
                    },
                )
            }))
        });

    // Later entries win, so a provider key replaces a direct one for the same organization.
    let keys = direct
        .chain(through_provider)
        .collect::<Result<HashMap<_, _>, _>>()
        .map_err(CryptoSyncDataParseError::OrganizationKey)?;

    Ok(keys
        .into_iter()
        .map(|(org_id, key)| OrganizationSharedKey { org_id, key })
        .collect())
}

/// Parses the keys of the providers the user is a member of. Memberships without a key are
/// skipped.
#[cfg(not(target_arch = "wasm32"))]
fn parse_provider_keys(
    profile: &bitwarden_api_api::models::ProfileResponseModel,
) -> Result<Vec<ProviderSharedKey>, CryptoSyncDataParseError> {
    profile
        .providers
        .iter()
        .flatten()
        .filter_map(|provider| {
            let (Some(id), Some(key)) = (provider.id, provider.key.as_deref()) else {
                return None;
            };
            Some(key.parse().map(|key| ProviderSharedKey {
                provider_id: ProviderId::new(id),
                key,
            }))
        })
        .collect::<Result<_, _>>()
        .map_err(CryptoSyncDataParseError::ProviderKey)
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<&bitwarden_api_api::models::UserDecryptionResponseModel> for CryptoSyncUserDecryption {
    type Error = CryptoSyncDataParseError;

    fn try_from(
        response: &bitwarden_api_api::models::UserDecryptionResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            master_password_unlock: response
                .master_password_unlock
                .as_deref()
                .map(MasterPasswordUnlockData::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::MasterPasswordUnlock)?,
            v2_upgrade_token: response
                .v2_upgrade_token
                .as_deref()
                .map(V2UpgradeToken::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::V2UpgradeToken)?,
            web_authn_prf_options: response
                .web_authn_prf_options
                .as_deref()
                .map(|options| {
                    options
                        .iter()
                        .map(WebAuthnPrfUnlockOption::try_from)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(CryptoSyncDataParseError::WebAuthnPrfOption)?,
            user_key_id: response
                .user_key_id
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(CryptoSyncDataParseError::UserKeyId)?,
        })
    }
}

/// Runs the key management sync work for the given sync data.
async fn handle_crypto_sync(client: &Client, data: &CryptoSyncData) {
    // A replayed payload is refused whole: taking its user decryption options would let the
    // server swap out the key id and unlock data that belong to the state it just tried to undo.
    if is_replayed_state(client, data).await {
        warn!("WARNING: Refusing a V2 to V1 account cryptographic state downgrade.");
        return;
    }

    // Handlers MUST NOT fail, to avoid partial state writes
    handle_user_decryption_options(client, data).await;
    handle_account_cryptographic_state(client, data).await;
    handle_v2_upgrade(client, data).await;
    // After the V2 upgrade, so organization keys are unwrapped with the current private key.
    handle_organization_keys(client, data).await;

    // Further key management sync handlers go here.
}

/// Persists the user decryption options the server reported.
async fn handle_user_decryption_options(client: &Client, data: &CryptoSyncData) {
    let Some(user_decryption) = data.user_decryption.as_ref() else {
        return;
    };

    // This is necessary until all clients implement the state bridge.
    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    match user_decryption.master_password_unlock.as_ref() {
        Some(master_password_unlock) => {
            state_bridge
                .set_masterpassword_unlock_data(master_password_unlock)
                .await;
            state_bridge
                .set_kdf_config(&master_password_unlock.kdf)
                .await;
        }
        None => state_bridge.clear_masterpassword_unlock_data().await,
    }

    match user_decryption.v2_upgrade_token.as_ref() {
        Some(v2_upgrade_token) => state_bridge.set_v2_upgrade_token(v2_upgrade_token).await,
        None => state_bridge.clear_v2_upgrade_token().await,
    }

    // An absent list and an empty list both mean the account has no PRF-capable credentials.
    match user_decryption.web_authn_prf_options.as_ref() {
        Some(options) if !options.is_empty() => {
            state_bridge
                .set_webauthn_prf_unlock_data(&WebAuthnPrfUnlockData {
                    options: options.clone(),
                })
                .await
        }
        _ => state_bridge.clear_webauthn_prf_unlock_data().await,
    }

    // The stored key id mirrors the server's. An absent one means the server has no id recorded for
    // this user key, so a previously stored id no longer describes anything and is dropped.
    match user_decryption.user_key_id.as_ref() {
        Some(user_key_id) => state_bridge.set_user_key_id(user_key_id).await,
        None => state_bridge.clear_user_key_id().await,
    }
}

/// Persists the account cryptographic state the server reported.
async fn handle_account_cryptographic_state(client: &Client, data: &CryptoSyncData) {
    let Some(incoming) = data.account_cryptographic_state.as_ref() else {
        return;
    };

    // This is necessary until all clients implement the state bridge.
    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    state_bridge.set_account_cryptographic_state(incoming).await;
}

/// Applies a V1 to V2 upgrade done on another device to an unlocked client.
///
/// The upgrade token and V2 state are stored above, but an unlocked client still holds the V1 user
/// key, in memory and in client state. Re-initializing swaps it for the V2 key and writes that
/// back, so the client does not prompt for a second, destructive, V2 to V2 rotation.
///
///   unlocked client (K1) ── sync(V2 state + token) ──▶ reinit ──▶ K2 in memory and in state
///   locked client       ── sync(V2 state + token) ──▶ nothing, the next unlock upgrades
#[cfg(any(feature = "uniffi", feature = "wasm"))]
async fn handle_v2_upgrade(client: &Client, data: &CryptoSyncData) {
    let Some(account_cryptographic_state) = data.account_cryptographic_state.clone() else {
        return;
    };
    let Some(upgrade_token) = data
        .user_decryption
        .as_ref()
        .and_then(|user_decryption| user_decryption.v2_upgrade_token.clone())
    else {
        return;
    };

    let result = client
        .crypto()
        .reinit_user_crypto(ReinitUserCryptoRequest {
            account_cryptographic_state,
            upgrade_token,
        })
        .await;

    match result {
        Ok(()) => {}
        Err(ReinitUserCryptoError::NotUnlocked) => debug!("Locked, skipping V2 upgrade reinit"),
        // Handlers MUST NOT fail, to avoid partial state writes
        Err(e) => warn!(error = ?e, "Failed to apply the V2 upgrade to the unlocked client"),
    }
}

#[cfg(not(any(feature = "uniffi", feature = "wasm")))]
async fn handle_v2_upgrade(_client: &Client, _data: &CryptoSyncData) {}

/// Persists the provider and organization keys the server reported, and reloads them into an
/// unlocked client.
///
///   unlocked client ── sync(keys) ──▶ persist ──▶ reload into the key store
///   locked client   ── sync(keys) ──▶ persist      the next unlock loads them
async fn handle_organization_keys(client: &Client, data: &CryptoSyncData) {
    if data.organization_keys.is_none() && data.provider_keys.is_none() {
        return;
    }

    // Providers first, since provider-wrapped organization keys depend on them.
    if let Some(provider_keys) = data.provider_keys.as_ref() {
        let values = provider_keys
            .iter()
            .map(|p| (p.provider_id, p.clone()))
            .collect();
        if let Err(e) = replace_all::<ProviderSharedKey>(client, values).await {
            // Handlers MUST NOT fail, to avoid partial state writes
            warn!(error = ?e, "Failed to persist provider keys");
        }
    }

    if let Some(organization_keys) = data.organization_keys.as_ref() {
        let values = organization_keys
            .iter()
            .map(|o| (o.org_id, o.clone()))
            .collect();
        if let Err(e) = replace_all::<OrganizationSharedKey>(client, values).await {
            // Handlers MUST NOT fail, to avoid partial state writes
            warn!(error = ?e, "Failed to persist organization keys");
        }
    }

    match client.crypto().load_organization_keys().await {
        Ok(_) => {}
        Err(OrganizationKeysError::NotUnlocked) => {
            debug!("Locked, skipping organization key reload")
        }
        Err(e) => warn!(error = ?e, "Failed to reload organization keys"),
    }
}

async fn replace_all<T: RepositoryItem>(
    client: &Client,
    values: Vec<(T::Key, T)>,
) -> Result<(), RepositoryError> {
    client
        .platform()
        .state()
        .get::<T>()?
        .replace_all(values)
        .await
}

/// Whether the sync carries a state that constitutes a cryptographic downgrade
///
/// Currently, the only downgrade defined is a V2 -> V1 encryption downgrade
async fn is_replayed_state(client: &Client, data: &CryptoSyncData) -> bool {
    let Some(incoming) = data.account_cryptographic_state.as_ref() else {
        return false;
    };
    let Some(local) = client
        .km_state_bridge()
        .get_account_cryptographic_state()
        .await
    else {
        return false;
    };

    if is_v2_to_v1_downgrade(&local, incoming) {
        return true;
    }

    // If we define more downgrade types in the future, check them here.
    false
}

/// Whether the incoming state moves a locally V2 account back to V1.
///
/// V1 accounts carry no security state, so staying on V1 or upgrading to V2 is never a downgrade.
fn is_v2_to_v1_downgrade(
    local: &WrappedAccountCryptographicState,
    incoming: &WrappedAccountCryptographicState,
) -> bool {
    matches!(local, WrappedAccountCryptographicState::V2 { .. })
        && matches!(incoming, WrappedAccountCryptographicState::V1 { .. })
}

/// Client for the key management work that runs on every sync.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct CryptoSyncHandlerClient {
    client: Client,
}

impl CryptoSyncHandlerClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl CryptoSyncHandlerClient {
    /// Runs the key management sync work. Call this after each sync, once the user's cryptographic
    /// state has been applied.
    pub async fn on_sync(&self, data: CryptoSyncData) {
        handle_crypto_sync(&self.client, &data).await
    }
}

/// Extension trait to add the key management sync handler client to the main Bitwarden SDK client.
pub trait CryptoSyncHandlerClientExt {
    /// Get the key management sync handler client.
    fn crypto_sync_handler(&self) -> CryptoSyncHandlerClient;
}

impl CryptoSyncHandlerClientExt for Client {
    fn crypto_sync_handler(&self) -> CryptoSyncHandlerClient {
        CryptoSyncHandlerClient::new(self.clone())
    }
}

/// [`bitwarden_sync::SyncHandler`] implementation of the same work, reading the sync data straight
/// off the generated sync response model.
///
/// Unused while the clients still own sync — they call [`CryptoSyncHandlerClient::on_sync`] instead
/// — but this is the entry point that survives once sync moves into the SDK.
///
/// Not available on `wasm32`: [`bitwarden_sync::SyncHandler`] requires `Send` futures, while the
/// generated `bitwarden-api-api` client is `?Send` on that target. `bitwarden-sync` is not exposed
/// to the wasm bindings either, so nothing is lost — wasm callers use
/// [`CryptoSyncHandlerClient::on_sync`].
#[cfg(not(target_arch = "wasm32"))]
pub struct CryptoSyncHandler {
    client: Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl CryptoSyncHandler {
    /// Creates a handler bound to the given client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl bitwarden_sync::SyncHandler for CryptoSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), bitwarden_sync::SyncHandlerError> {
        // Parsing happens up front so that a malformed response fails the sync without having
        // written any state.
        let data = CryptoSyncData::try_from(response)?;

        handle_crypto_sync(&self.client, &data).await;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use bitwarden_api_api::models::{
        KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
        ProfileOrganizationResponseModel, ProfileProviderOrganizationResponseModel,
        ProfileProviderResponseModel, ProfileResponseModel, SyncResponseModel,
        UserDecryptionResponseModel, WebAuthnPrfDecryptionOption,
    };
    use bitwarden_core::key_management::{
        KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId,
        state_bridge::test_support::InMemoryStateBridge,
    };
    use bitwarden_crypto::{
        KeyStore, PublicKey, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm, UnsignedSharedKey,
    };
    use uuid::Uuid;

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_SALT: &str = "test@example.com";
    const TEST_USER_KEY_ID: &str = "000102030405060708090a0b0c0d0e0f";

    fn master_password_unlock(
        master_key_encrypted_user_key: Option<String>,
    ) -> MasterPasswordUnlockResponseModel {
        MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key,
            salt: Some(TEST_SALT.to_string()),
            contained_key_id: None,
        }
    }

    fn sync_response(user_decryption: UserDecryptionResponseModel) -> SyncResponseModel {
        SyncResponseModel {
            user_decryption: Some(Box::new(user_decryption)),
            ..Default::default()
        }
    }

    #[test]
    fn test_try_from_empty_response_is_empty_data() {
        let data = CryptoSyncData::try_from(&SyncResponseModel::default()).unwrap();

        assert!(data.user_decryption.is_none());
        assert!(data.account_cryptographic_state.is_none());
        assert!(data.organization_keys.is_none());
        assert!(data.provider_keys.is_none());
    }

    const TEST_UNSIGNED_SHARED_KEY: &str = "4.rY01mZFXHOsBAg5Fq4gyXuklWfm6mQASm42DJpx05a+e2mmp+P5W6r54WU2hlREX0uoTxyP91bKKwickSPdCQQ58J45LXHdr9t2uzOYyjVzpzebFcdMw1eElR9W2DW8wEk9+mvtWvKwu7yTebzND+46y1nRMoFydi5zPVLSlJEf81qZZ4Uh1UUMLwXz+NRWfixnGXgq2wRq1bH0n3mqDhayiG4LJKgGdDjWXC8W8MMXDYx24SIJrJu9KiNEMprJE+XVF9nQVNijNAjlWBqkDpsfaWTUfeVLRLctfAqW1blsmIv4RQ91PupYJZDNc8nO9ZTF3TEVM+2KHoxzDJrLs2Q==";
    const ORG_ID: Uuid = Uuid::from_u128(1);
    const PROVIDER_ORG_ID: Uuid = Uuid::from_u128(2);
    const PROVIDER_ID: Uuid = Uuid::from_u128(3);

    fn profile_response(profile: ProfileResponseModel) -> SyncResponseModel {
        SyncResponseModel {
            profile: Some(Box::new(profile)),
            ..Default::default()
        }
    }

    fn member_organization(id: Uuid, key: Option<&str>) -> ProfileOrganizationResponseModel {
        ProfileOrganizationResponseModel {
            id: Some(id),
            key: key.map(str::to_owned),
            ..Default::default()
        }
    }

    fn provider_organization(
        id: Uuid,
        key: Option<&str>,
    ) -> ProfileProviderOrganizationResponseModel {
        ProfileProviderOrganizationResponseModel {
            id: Some(id),
            provider_id: Some(PROVIDER_ID),
            key: key.map(str::to_owned),
            ..Default::default()
        }
    }

    fn provider(key: Option<&str>) -> ProfileProviderResponseModel {
        ProfileProviderResponseModel {
            id: Some(PROVIDER_ID),
            key: key.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn test_try_from_parses_organization_and_provider_keys() {
        let response = profile_response(ProfileResponseModel {
            organizations: Some(vec![member_organization(
                ORG_ID,
                Some(TEST_UNSIGNED_SHARED_KEY),
            )]),
            provider_organizations: Some(vec![provider_organization(
                PROVIDER_ORG_ID,
                Some(TEST_USER_KEY),
            )]),
            providers: Some(vec![provider(Some(TEST_UNSIGNED_SHARED_KEY))]),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let mut organization_keys = data.organization_keys.unwrap();
        organization_keys.sort_by_key(|o| o.org_id);
        let [direct, through_provider] = organization_keys.as_slice() else {
            panic!("expected two organization keys");
        };
        assert_eq!(direct.org_id, OrganizationId::new(ORG_ID));
        assert!(matches!(
            direct.key,
            OrganizationKeyEnvelope::Organization { .. }
        ));
        assert_eq!(
            through_provider.org_id,
            OrganizationId::new(PROVIDER_ORG_ID)
        );
        assert!(matches!(
            through_provider.key,
            OrganizationKeyEnvelope::Provider { provider_id, .. }
                if provider_id == ProviderId::new(PROVIDER_ID)
        ));

        let provider_keys = data.provider_keys.unwrap();
        assert_eq!(provider_keys.len(), 1);
        assert_eq!(provider_keys[0].provider_id, ProviderId::new(PROVIDER_ID));
    }

    /// An invited but unconfirmed member has no key yet.
    #[test]
    fn test_try_from_skips_memberships_without_a_key() {
        let response = profile_response(ProfileResponseModel {
            organizations: Some(vec![member_organization(ORG_ID, None)]),
            provider_organizations: Some(vec![provider_organization(PROVIDER_ORG_ID, None)]),
            providers: Some(vec![provider(None)]),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        assert!(data.organization_keys.unwrap().is_empty());
        assert!(data.provider_keys.unwrap().is_empty());
    }

    #[test]
    fn test_try_from_prefers_the_provider_key_for_an_organization() {
        let response = profile_response(ProfileResponseModel {
            organizations: Some(vec![member_organization(
                ORG_ID,
                Some(TEST_UNSIGNED_SHARED_KEY),
            )]),
            provider_organizations: Some(vec![provider_organization(ORG_ID, Some(TEST_USER_KEY))]),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let organization_keys = data.organization_keys.unwrap();
        assert_eq!(organization_keys.len(), 1);
        assert!(matches!(
            organization_keys[0].key,
            OrganizationKeyEnvelope::Provider { .. }
        ));
    }

    #[test]
    fn test_try_from_malformed_organization_key_errors() {
        let response = profile_response(ProfileResponseModel {
            organizations: Some(vec![member_organization(ORG_ID, Some("not a key"))]),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::OrganizationKey(_))
        ));
    }

    #[test]
    fn test_try_from_malformed_provider_key_errors() {
        let response = profile_response(ProfileResponseModel {
            providers: Some(vec![provider(Some("not a key"))]),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::ProviderKey(_))
        ));
    }

    #[test]
    fn test_try_from_valid_master_password_unlock_succeeds() {
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(Some(
                TEST_USER_KEY.to_string(),
            )))),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let user_decryption = data.user_decryption.unwrap();
        assert_eq!(
            user_decryption.master_password_unlock.unwrap().salt,
            TEST_SALT
        );
    }

    #[test]
    fn test_try_from_malformed_master_password_unlock_errors() {
        // Missing wrapped user key.
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(None))),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::MasterPasswordUnlock(_))
        ));
    }

    #[test]
    fn test_try_from_malformed_webauthn_prf_option_errors() {
        let response = sync_response(UserDecryptionResponseModel {
            web_authn_prf_options: Some(vec![WebAuthnPrfDecryptionOption::default()]),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::WebAuthnPrfOption(_))
        ));
    }

    #[test]
    fn test_try_from_valid_user_key_id_succeeds() {
        let response = sync_response(UserDecryptionResponseModel {
            user_key_id: Some(TEST_USER_KEY_ID.to_string()),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let user_key_id = data.user_decryption.unwrap().user_key_id.unwrap();
        assert_eq!(user_key_id.to_string(), TEST_USER_KEY_ID);
    }

    #[test]
    fn test_try_from_absent_user_key_id_is_none() {
        // The account has other unlock data, but the server has no key id recorded for it yet.
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(Some(
                TEST_USER_KEY.to_string(),
            )))),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        assert!(data.user_decryption.unwrap().user_key_id.is_none());
    }

    #[test]
    fn test_try_from_malformed_user_key_id_errors() {
        for malformed in [
            "not hex at all",
            // Valid hex, but not 16 bytes worth.
            "00ff",
            // Odd number of hex digits.
            "000102030405060708090a0b0c0d0e0",
        ] {
            let response = sync_response(UserDecryptionResponseModel {
                user_key_id: Some(malformed.to_string()),
                ..Default::default()
            });

            assert!(
                matches!(
                    CryptoSyncData::try_from(&response),
                    Err(CryptoSyncDataParseError::UserKeyId(_))
                ),
                "{malformed:?} should not parse as a key id"
            );
        }
    }

    /// The key id has to reach the state bridge, not just the parsed data. An absent id clears a
    /// previously stored one.
    #[tokio::test]
    async fn test_handle_crypto_sync_writes_and_clears_user_key_id() {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));

        let with_key_id = CryptoSyncData::try_from(&sync_response(UserDecryptionResponseModel {
            user_key_id: Some(TEST_USER_KEY_ID.to_string()),
            ..Default::default()
        }))
        .unwrap();
        handle_crypto_sync(&client, &with_key_id).await;

        let stored = client.km_state_bridge().get_user_key_id().await.unwrap();
        assert_eq!(stored.to_string(), TEST_USER_KEY_ID);

        let without_key_id =
            CryptoSyncData::try_from(&sync_response(UserDecryptionResponseModel::default()))
                .unwrap();
        handle_crypto_sync(&client, &without_key_id).await;

        assert!(client.km_state_bridge().get_user_key_id().await.is_none());
    }

    /// A client with an in-memory state bridge registered.
    fn client_with_bridge() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
    }

    fn make_v2_state() -> WrappedAccountCryptographicState {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (_, state) =
            WrappedAccountCryptographicState::make(&mut ctx).expect("making a V2 state succeeds");
        state
    }

    fn make_v1_state() -> WrappedAccountCryptographicState {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        WrappedAccountCryptographicState::V1 {
            private_key: ctx
                .wrap_private_key(user_key, private_key)
                .expect("wrapping the private key succeeds"),
        }
    }

    /// Runs the handler for the given incoming state and returns what the bridge holds afterwards.
    async fn sync_account_cryptographic_state(
        client: &Client,
        incoming: &WrappedAccountCryptographicState,
    ) -> Option<WrappedAccountCryptographicState> {
        let data = CryptoSyncData {
            account_cryptographic_state: Some(incoming.clone()),
            ..Default::default()
        };
        handle_crypto_sync(client, &data).await;
        client
            .km_state_bridge()
            .get_account_cryptographic_state()
            .await
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_is_persisted_when_there_is_no_local_state() {
        let client = client_with_bridge();
        let incoming = make_v2_state();

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_upgrade_from_v1_to_v2_is_persisted() {
        let client = client_with_bridge();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&make_v1_state())
            .await;
        let incoming = make_v2_state();

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_downgrade_from_v2_to_v1_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;

        let stored = sync_account_cryptographic_state(&client, &make_v1_state()).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    /// A client unlocked with a fresh user key and private key. Returns the user's public key.
    fn unlocked_client() -> (Client, PublicKey) {
        let client = Client::new(None);
        let public_key = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .expect("persisting the user key succeeds");
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.persist_private_key(private_key, PrivateKeySlotId::UserPrivateKey)
                .expect("persisting the private key succeeds");
            ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)
                .expect("the private key is present")
        };
        (client, public_key)
    }

    /// A fresh organization key, encapsulated to `public_key`.
    fn organization_key(id: Uuid, public_key: &PublicKey) -> OrganizationSharedKey {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        OrganizationSharedKey {
            org_id: OrganizationId::new(id),
            key: OrganizationKeyEnvelope::Organization {
                key: UnsignedSharedKey::encapsulate(key, public_key, &ctx)
                    .expect("encapsulation succeeds"),
            },
        }
    }

    async fn sync_organization_keys(client: &Client, keys: Option<Vec<OrganizationSharedKey>>) {
        let data = CryptoSyncData {
            organization_keys: keys,
            ..Default::default()
        };
        handle_crypto_sync(client, &data).await;
    }

    async fn persisted_organization_ids(client: &Client) -> Vec<OrganizationId> {
        let mut ids: Vec<_> = client
            .platform()
            .state()
            .get::<OrganizationSharedKey>()
            .expect("repository is registered")
            .list()
            .await
            .expect("listing succeeds")
            .into_iter()
            .map(|o| o.org_id)
            .collect();
        ids.sort();
        ids
    }

    fn has_organization_key(client: &Client, id: Uuid) -> bool {
        client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::Organization(OrganizationId::new(id)))
    }

    #[tokio::test]
    async fn test_organization_keys_absent_leaves_state_alone() {
        let (client, public_key) = unlocked_client();
        sync_organization_keys(&client, Some(vec![organization_key(ORG_ID, &public_key)])).await;

        sync_organization_keys(&client, None).await;

        assert_eq!(
            persisted_organization_ids(&client).await,
            vec![OrganizationId::new(ORG_ID)]
        );
        assert!(has_organization_key(&client, ORG_ID));
    }

    #[tokio::test]
    async fn test_organization_keys_empty_clears_state_and_key_store() {
        let (client, public_key) = unlocked_client();
        sync_organization_keys(&client, Some(vec![organization_key(ORG_ID, &public_key)])).await;

        sync_organization_keys(&client, Some(vec![])).await;

        assert!(persisted_organization_ids(&client).await.is_empty());
        assert!(!has_organization_key(&client, ORG_ID));
    }

    #[tokio::test]
    async fn test_organization_keys_drop_organizations_the_user_left() {
        let (client, public_key) = unlocked_client();
        let kept = organization_key(ORG_ID, &public_key);
        let left = organization_key(PROVIDER_ORG_ID, &public_key);
        sync_organization_keys(&client, Some(vec![kept.clone(), left])).await;

        sync_organization_keys(&client, Some(vec![kept])).await;

        assert_eq!(
            persisted_organization_ids(&client).await,
            vec![OrganizationId::new(ORG_ID)]
        );
        assert!(has_organization_key(&client, ORG_ID));
        assert!(!has_organization_key(&client, PROVIDER_ORG_ID));
    }

    #[tokio::test]
    async fn test_organization_keys_reload_into_an_unlocked_client() {
        let (client, public_key) = unlocked_client();

        sync_organization_keys(&client, Some(vec![organization_key(ORG_ID, &public_key)])).await;

        assert!(has_organization_key(&client, ORG_ID));
    }

    #[tokio::test]
    async fn test_organization_keys_persist_without_loading_into_a_locked_client() {
        let client = Client::new(None);
        let (_, public_key) = unlocked_client();

        sync_organization_keys(&client, Some(vec![organization_key(ORG_ID, &public_key)])).await;

        assert_eq!(
            persisted_organization_ids(&client).await,
            vec![OrganizationId::new(ORG_ID)]
        );
        assert!(!has_organization_key(&client, ORG_ID));
    }
}
